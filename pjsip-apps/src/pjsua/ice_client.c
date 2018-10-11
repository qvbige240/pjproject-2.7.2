/* $Id: pjsua_app.c 5677 2017-10-27 06:30:50Z ming $ */
/* 
* Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
* Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
*/
#include "ice_client.h"

#define THIS_FILE	"ice_client.c"

#if defined(PJMEDIA_HAS_RTCP_XR) && (PJMEDIA_HAS_RTCP_XR != 0)
#   define SOME_BUF_SIZE	(1024 * 10)
#else
#   define SOME_BUF_SIZE	(1024 * 3)
#endif

static char some_buf[SOME_BUF_SIZE];

pjsua_call_id	    current_call = PJSUA_INVALID_ID;
pjsua_app_config    app_config = {0};
pjsua_call_setting  call_opt;

/* Set default config. */
static void default_config()
{
	char tmp[80];
	unsigned i;
	pjsua_app_config *cfg = &app_config;

	pjsua_config_default(&cfg->cfg);
	pj_ansi_sprintf(tmp, "TIMA v%s %s", pj_get_version(), pj_get_sys_info()->info.ptr);
	pj_strdup2_with_null(app_config.pool, &cfg->cfg.user_agent, tmp);

	pjsua_logging_config_default(&cfg->log_cfg);
	pjsua_media_config_default(&cfg->media_cfg);
	pjsua_transport_config_default(&cfg->udp_cfg);
	cfg->udp_cfg.port = 5060;
	pjsua_transport_config_default(&cfg->rtp_cfg);
	cfg->rtp_cfg.port = 4000;
	cfg->redir_op = PJSIP_REDIRECT_ACCEPT_REPLACE;
	cfg->duration = PJSUA_APP_NO_LIMIT_DURATION;
	cfg->wav_id = PJSUA_INVALID_ID;
	cfg->rec_id = PJSUA_INVALID_ID;
	cfg->wav_port = PJSUA_INVALID_ID;
	cfg->rec_port = PJSUA_INVALID_ID;
	cfg->mic_level = cfg->speaker_level = 1.0;
	cfg->capture_dev = PJSUA_INVALID_ID;
	cfg->playback_dev = PJSUA_INVALID_ID;
	cfg->capture_lat = PJMEDIA_SND_DEFAULT_REC_LATENCY;
	cfg->playback_lat = PJMEDIA_SND_DEFAULT_PLAY_LATENCY;
	cfg->ringback_slot = PJSUA_INVALID_ID;
	cfg->ring_slot = PJSUA_INVALID_ID;

	for (i=0; i<PJ_ARRAY_SIZE(cfg->acc_cfg); ++i)
		pjsua_acc_config_default(&cfg->acc_cfg[i]);

 	for (i=0; i<PJ_ARRAY_SIZE(cfg->buddy_cfg); ++i)
 		pjsua_buddy_config_default(&cfg->buddy_cfg[i]);

	cfg->vid.vcapture_dev = PJMEDIA_VID_DEFAULT_CAPTURE_DEV;
	cfg->vid.vrender_dev = PJMEDIA_VID_DEFAULT_RENDER_DEV;
	cfg->aud_cnt = 1;

	cfg->avi_def_idx = PJSUA_INVALID_ID;

	//cfg->use_cli = PJ_FALSE;
	//cfg->cli_cfg.cli_fe = CLI_FE_CONSOLE;
	//cfg->cli_cfg.telnet_cfg.port = 0;
}

//typedef struct ice_info_s
//{
//	char	account[32];	// 102
//	char	passwd[32];		// 102
//	char	server[32];	// "172.17.13.8"
//	char	realm[32];	// "172.17.13.8"
//
//	char	turn[32];	// "172.17.13.8:3488"
//	char	username[32];	// username2
//	char	password[32];	// password2
//
//	int		conn_type;
//} ice_info_t;

typedef struct socket_client
{
	void				*ctx;
	iclient_callback	cb;

	void				*tp;
	int					connected;
} socket_client;


/*
* Find next call when current call is disconnected or when user
* press ']'
*/
pj_bool_t find_next_call()
{
	int i, max;

	max = pjsua_call_get_max_count();
	for (i=current_call+1; i<max; ++i) {
		if (pjsua_call_is_active(i)) {
			current_call = i;
			return PJ_TRUE;
		}
	}

	for (i=0; i<current_call; ++i) {
		if (pjsua_call_is_active(i)) {
			current_call = i;
			return PJ_TRUE;
		}
	}

	current_call = PJSUA_INVALID_ID;
	return PJ_FALSE;
}

pj_bool_t find_prev_call()
{
	int i, max;

	max = pjsua_call_get_max_count();
	for (i=current_call-1; i>=0; --i) {
		if (pjsua_call_is_active(i)) {
			current_call = i;
			return PJ_TRUE;
		}
	}

	for (i=max-1; i>current_call; --i) {
		if (pjsua_call_is_active(i)) {
			current_call = i;
			return PJ_TRUE;
		}
	}

	current_call = PJSUA_INVALID_ID;
	return PJ_FALSE;
}

/*
* Print log of call states. Since call states may be too long for logger,
* printing it is a bit tricky, it should be printed part by part as long 
* as the logger can accept.
*/
void log_call_dump(int call_id) 
{
	unsigned call_dump_len;
	unsigned part_len;
	unsigned part_idx;
	unsigned log_decor;

	pjsua_call_dump(call_id, PJ_TRUE, some_buf, sizeof(some_buf), "  ");
	call_dump_len = (unsigned)strlen(some_buf);

	log_decor = pj_log_get_decor();
	pj_log_set_decor(log_decor & ~(PJ_LOG_HAS_NEWLINE | PJ_LOG_HAS_CR));
	PJ_LOG(3,(THIS_FILE, "\n"));
	pj_log_set_decor(0);

	part_idx = 0;
	part_len = PJ_LOG_MAX_SIZE-80;
	while (part_idx < call_dump_len) {
		char p_orig, *p;

		p = &some_buf[part_idx];
		if (part_idx + part_len > call_dump_len)
			part_len = call_dump_len - part_idx;
		p_orig = p[part_len];
		p[part_len] = '\0';
		PJ_LOG(3,(THIS_FILE, "%s", p));
		p[part_len] = p_orig;
		part_idx += part_len;
	}
	pj_log_set_decor(log_decor);
}

/*
* Print account status.
*/
static void print_acc_status(int acc_id)
{
	char buf[80];
	pjsua_acc_info info;

	pjsua_acc_get_info(acc_id, &info);

	if (!info.has_registration) {
		pj_ansi_snprintf(buf, sizeof(buf), "%.*s",
			(int)info.status_text.slen,
			info.status_text.ptr);

	} else {
		pj_ansi_snprintf(buf, sizeof(buf),
			"%d/%.*s (expires=%d)",
			info.status,
			(int)info.status_text.slen,
			info.status_text.ptr,
			info.expires);

	}

	printf(" %c[%2d] %.*s: %s\n", (acc_id==current_acc?'*':' '),
		acc_id,  (int)info.acc_uri.slen, info.acc_uri.ptr, buf);
	printf("       Online status: %.*s\n",
		(int)info.online_status_text.slen,
		info.online_status_text.ptr);
}

/*
* Show a bit of help.
*/
static void keystroke_help()
{
	pjsua_acc_id acc_ids[16];
	unsigned count = PJ_ARRAY_SIZE(acc_ids);
	int i;

	printf(">>>>\n");

	pjsua_enum_accs(acc_ids, &count);

	printf("Account list:\n");
	for (i=0; i<(int)count; ++i)
		print_acc_status(acc_ids[i]);

	//print_buddy_list();

	//puts("Commands:");
	puts("+=============================================================================+");
	puts("|       Call Commands:         |   Buddy, IM & Presence:  |     Account:      |");
	puts("|                              |                          |                   |");
	puts("|  m  Make new call            | +b  Add new buddy       .| +a  Add new accnt |");
	puts("|  M  Make multiple calls      | -b  Delete buddy         | -a  Delete accnt. |");
	puts("|  a  Answer call              |  i  Send IM              | !a  Modify accnt. |");
	puts("|  h  Hangup call  (ha=all)    |  s  Subscribe presence   | rr  (Re-)register |");
	puts("|  H  Hold call                |  u  Unsubscribe presence | ru  Unregister    |");
	puts("|  v  re-inVite (release hold) |  t  ToGgle Online status |  >  Cycle next ac.|");
	puts("|  U  send UPDATE              |  T  Set online status    |  <  Cycle prev ac.|");
	puts("| ],[ Select next/prev call    +--------------------------+-------------------+");
	puts("|  x  Xfer call                |      Media Commands:     |  Status & Config: |");
	puts("|  X  Xfer with Replaces       |                          |                   |");
	puts("|  #  Send RFC 2833 DTMF       | cl  List ports           |  d  Dump status   |");
	puts("|  *  Send DTMF with INFO      | cc  Connect port         | dd  Dump detailed |");
	puts("| dq  Dump curr. call quality  | cd  Disconnect port      | dc  Dump config   |");
	puts("|                              |  V  Adjust audio Volume  |  f  Save config   |");
	puts("|  S  Send arbitrary REQUEST   | Cp  Codec priorities     |                   |");
	puts("+-----------------------------------------------------------------------------+");
#if PJSUA_HAS_VIDEO
	puts("| Video: \"vid help\" for more info                                             |");
	puts("+-----------------------------------------------------------------------------+");
#endif
	puts("|  q  QUIT   L  ReLoad   sleep MS   echo [0|1|txt]     n: detect NAT type     |");
	puts("+=============================================================================+");

	i = pjsua_call_get_count();
	printf("You have %d active call%s\n", i, (i>1?"s":""));

	if (current_call != PJSUA_INVALID_ID) {
		pjsua_call_info ci;
		if (pjsua_call_get_info(current_call, &ci)==PJ_SUCCESS)
			printf("Current call id=%d to %.*s [%.*s]\n", current_call,
			(int)ci.remote_info.slen, ci.remote_info.ptr,
			(int)ci.state_text.slen, ci.state_text.ptr);
	}
}

char* pj_strdup0(pj_pool_t *pool, char **dst, const char *src)
{
	pj_ssize_t slen = src ? pj_ansi_strlen(src) : 0;
	if (slen) {
		*dst = (char*)pj_pool_alloc(pool, slen);
		pj_memcpy(*dst, src, slen);
	} else {
		*dst = NULL;
	}
	return *dst;
}

static pj_status_t set_args(ice_info_t *info)
{
	int i;
	pjsua_app_config *cfg = &app_config;
	pjsua_acc_config *cur_acc;

	cfg->acc_cnt = 0;
	cur_acc = cfg->acc_cfg;

	PJ_ASSERT_RETURN(info, PJ_EINVAL);

	char *id, *turn, *url;
	char id_tmp[128] = {0}, turn_tmp[64] = {0}, url_tmp[32] = {0};
	sprintf(id_tmp, "sip:%s@%s", info->account, info->server);
	sprintf(turn_tmp, "%s:%s", info->turn, info->turn_port);
	sprintf(url_tmp, "sip:%s", info->server);
	//char* id = "sip:102@172.17.13.8";
	pj_strdup0(app_config.pool, &id, id_tmp);
	pj_strdup0(app_config.pool, &turn, turn_tmp);
	pj_strdup0(app_config.pool, &url, url_tmp);

	/* id */
	if (pjsua_verify_url(id) != 0) {
		PJ_LOG(1, (THIS_FILE, "Error: invalid SIP URL '%s' in local id argument", id));
		return PJ_EINVAL;
	}
	cur_acc->id = pj_str(id);	// "sip:102@172.17.13.8"

	/* registrar */
	if (pjsua_verify_sip_url(url) != 0) {
		PJ_LOG(1,(THIS_FILE, "Error: invalid SIP URL '%s' in registrar argument", url));
		return PJ_EINVAL;
	}
	cur_acc->reg_uri = pj_str(url);	// "sip:172.17.13.8"

	/* Default authentication realm. */
	cur_acc->cred_info[cur_acc->cred_count].realm = pj_str(info->realm);
	/* Default authentication user */
	cur_acc->cred_info[cur_acc->cred_count].username = pj_str(info->account);
	cur_acc->cred_info[cur_acc->cred_count].scheme = pj_str("Digest");
	/* authentication password */
	cur_acc->cred_info[cur_acc->cred_count].data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
	cur_acc->cred_info[cur_acc->cred_count].data = pj_str(info->passwd);

	/* STUN server */
	cfg->cfg.stun_host = pj_str(info->server);
	if (cfg->cfg.stun_srv_cnt == PJ_ARRAY_SIZE(cfg->cfg.stun_srv)) {
		PJ_LOG(1, (THIS_FILE, "Error: too many STUN servers"));
		return PJ_ETOOMANY;
	}
	cfg->cfg.stun_srv[cfg->cfg.stun_srv_cnt++] = pj_str(info->server);

	cfg->media_cfg.enable_ice = cur_acc->ice_cfg.enable_ice = PJ_TRUE;
	cfg->media_cfg.enable_turn = cur_acc->turn_cfg.enable_turn = PJ_TRUE;

	cfg->media_cfg.turn_server = cur_acc->turn_cfg.turn_server = pj_str(turn);
	cfg->media_cfg.turn_conn_type = cur_acc->turn_cfg.turn_conn_type = PJ_TURN_TP_TCP;

	cfg->media_cfg.turn_auth_cred.type =
		cur_acc->turn_cfg.turn_auth_cred.type = PJ_STUN_AUTH_CRED_STATIC;
	cfg->media_cfg.turn_auth_cred.data.static_cred.realm =
		cur_acc->turn_cfg.turn_auth_cred.data.static_cred.realm = pj_str("*");
	cfg->media_cfg.turn_auth_cred.data.static_cred.username =
		cur_acc->turn_cfg.turn_auth_cred.data.static_cred.username = pj_str(info->username);

	cfg->media_cfg.turn_auth_cred.data.static_cred.data_type =
		cur_acc->turn_cfg.turn_auth_cred.data.static_cred.data_type = PJ_STUN_PASSWD_PLAIN;
	cfg->media_cfg.turn_auth_cred.data.static_cred.data =
		cur_acc->turn_cfg.turn_auth_cred.data.static_cred.data = pj_str(info->password);

	cfg->auto_answer = 200;

	if (cfg->acc_cfg[cfg->acc_cnt].id.slen)
		cfg->acc_cnt++;

	cur_acc->cred_count++;
	cur_acc->ice_cfg_use = PJSUA_ICE_CONFIG_USE_CUSTOM;
	cur_acc->turn_cfg_use = PJSUA_TURN_CONFIG_USE_CUSTOM;

	//for (i = 0; i < cfg->acc_cnt; ++i) {
	//	pjsua_acc_config *acfg = &cfg->acc_cfg[i];

	//	if (acfg->cred_info[acfg->cred_count].username.slen)
	//		acfg->cred_count++;

	//	if (acfg->ice_cfg.enable_ice)
	//		acfg->ice_cfg_use = PJSUA_ICE_CONFIG_USE_CUSTOM;

	//	if (acfg->turn_cfg.enable_turn)
	//		acfg->turn_cfg_use = PJSUA_TURN_CONFIG_USE_CUSTOM;
	//}

	return PJ_SUCCESS;
}


/*
* Handler when invite state has changed.
*/
static void on_call_state(pjsua_call_id call_id, pjsip_event *e)
{
	pjsua_call_info call_info;

	PJ_UNUSED_ARG(e);

	pjsua_call_get_info(call_id, &call_info);

	PJ_LOG(3,(THIS_FILE, "============Call %d state changed to %s", call_id, call_info.state_text.ptr));

	if (call_info.state == PJSIP_INV_STATE_DISCONNECTED) {
		///* Stop all ringback for this call */
		//ring_stop(call_id);

		/* Cancel duration timer, if any */
		if (app_config.call_data[call_id].timer.id != PJSUA_INVALID_ID) {
			app_call_data *cd = &app_config.call_data[call_id];
			pjsip_endpoint *endpt = pjsua_get_pjsip_endpt();

			cd->timer.id = PJSUA_INVALID_ID;
			pjsip_endpt_cancel_timer(endpt, &cd->timer);
		}

		///* Rewind play file when hangup automatically, 
		//* since file is not looped
		//*/
		//if (app_config.auto_play_hangup)
		//	pjsua_player_set_pos(app_config.wav_id, 0);

		PJ_LOG(3,(THIS_FILE, "Call %d is DISCONNECTED [reason=%d (%s)]", 
			call_id, call_info.last_status, call_info.last_status_text.ptr));

		if (call_id == current_call) {
			find_next_call();
		}

		/* Dump media state upon disconnected */
		if (1) {
			PJ_LOG(5,(THIS_FILE, "Call %d disconnected, dumping media stats..", call_id));
			log_call_dump(call_id);
		}

	} else {

		if (app_config.duration != PJSUA_APP_NO_LIMIT_DURATION && 
			call_info.state == PJSIP_INV_STATE_CONFIRMED) 
		{
			/* Schedule timer to hangup call after the specified duration */
			app_call_data *cd = &app_config.call_data[call_id];
			pjsip_endpoint *endpt = pjsua_get_pjsip_endpt();
			pj_time_val delay;

			cd->timer.id = call_id;
			delay.sec = app_config.duration;
			delay.msec = 0;
			pjsip_endpt_schedule_timer(endpt, &cd->timer, &delay);
		}

		if (call_info.state == PJSIP_INV_STATE_EARLY) {
			int code;
			pj_str_t reason;
			pjsip_msg *msg;

			/* This can only occur because of TX or RX message */
			pj_assert(e->type == PJSIP_EVENT_TSX_STATE);

			if (e->body.tsx_state.type == PJSIP_EVENT_RX_MSG) {
				msg = e->body.tsx_state.src.rdata->msg_info.msg;
			} else {
				msg = e->body.tsx_state.src.tdata->msg;
			}

			code = msg->line.status.code;
			reason = msg->line.status.reason;

			///* Start ringback for 180 for UAC unless there's SDP in 180 */
			//if (call_info.role==PJSIP_ROLE_UAC && code==180 && 
			//	msg->body == NULL && 
			//	call_info.media_status==PJSUA_CALL_MEDIA_NONE) 
			//{
			//	ringback_start(call_id);
			//}

			PJ_LOG(3,(THIS_FILE, "Call %d state changed to %s (%d %.*s)", 
				call_id, call_info.state_text.ptr, code, (int)reason.slen, reason.ptr));
		} else {
			PJ_LOG(3,(THIS_FILE, "Call %d state changed to %s", 
				call_id, call_info.state_text.ptr));
		}

		if (current_call==PJSUA_INVALID_ID)
			current_call = call_id;

	}
}

/**
 * Handler when there is incoming call.
 */
static void on_incoming_call(pjsua_acc_id acc_id, pjsua_call_id call_id, pjsip_rx_data *rdata)
{
	pjsua_call_info call_info;

	PJ_UNUSED_ARG(acc_id);
	PJ_UNUSED_ARG(rdata);

	pjsua_call_get_info(call_id, &call_info);

	if (current_call==PJSUA_INVALID_ID)
		current_call = call_id;

	if (app_config.auto_answer > 0) {
		pjsua_call_setting opt;

		pjsua_call_setting_default(&opt);
		opt.aud_cnt = app_config.aud_cnt;
		opt.vid_cnt = app_config.vid.vid_cnt;

		pjsua_call_answer2(call_id, &opt, app_config.auto_answer, NULL, NULL);
	}

	if (app_config.auto_answer < 200) {
		PJ_LOG(3,(THIS_FILE, "Incoming call, answer %d error", app_config.auto_answer));
	}
}
/*
 * Handler registration status has changed.
 */
static void on_reg_state(pjsua_acc_id acc_id)
{
	PJ_UNUSED_ARG(acc_id);

	// Log already written.
}

/*
 * NAT type detection callback.
 */
static void on_nat_detect(const pj_stun_nat_detect_result *res)
{
	if (res->status != PJ_SUCCESS) {
		pjsua_perror(THIS_FILE, "NAT detection failed", res->status);
	} else {
		PJ_LOG(3, (THIS_FILE, "NAT detected as %s", res->nat_type_name));
	}
}

/*
 * ice negotiation success callback.
 */
static void on_ice_negotiation_success(void *ctx, void *param)
{
	PJ_LOG(4, (THIS_FILE, "========ice negotiation success."));
}

/*
 * ice connect successfully callback.
 */
static void on_ice_connection_success(void *tp, void *param)
{
	socket_client *client = (socket_client *)app_config.client;

	PJ_LOG(4, (THIS_FILE, "========ice connection success."));
	if (tp && client) {
		client->tp = tp;
		client->connected = 1;
		if (client->cb.on_connect_success)
			client->cb.on_connect_success(client->ctx, NULL);
		else
			PJ_LOG(3, (THIS_FILE, "without register callback function: on_connect_success."));
	} else {
		PJ_LOG(3, (THIS_FILE, "null pointer error."));
	}
}

/*
 * ice receive message callback.
 */
static void on_ice_receive_message(void *data, void *pkt, pj_ssize_t bytes_read)
{
	socket_client *client = (socket_client *)app_config.client;
	if (client && client->cb.on_receive_message) {
		client->cb.on_receive_message(client->ctx, pkt, bytes_read);
	}
}

/* Callback from timer when the maximum call duration has been
 * exceeded.
 */
static void call_timeout_callback(pj_timer_heap_t *timer_heap, struct pj_timer_entry *entry)
{
	pjsua_call_id call_id = entry->id;
	pjsua_msg_data msg_data_;
	pjsip_generic_string_hdr warn;
	pj_str_t hname = pj_str("Warning");
	pj_str_t hvalue = pj_str("399 pjsua \"Call duration exceeded\"");

	PJ_UNUSED_ARG(timer_heap);

	if (call_id == PJSUA_INVALID_ID) {
		PJ_LOG(1,(THIS_FILE, "Invalid call ID in timer callback"));
		return;
	}

	/* Add warning header */
	pjsua_msg_data_init(&msg_data_);
	pjsip_generic_string_hdr_init2(&warn, &hname, &hvalue);
	pj_list_push_back(&msg_data_.hdr_list, &warn);

	/* Call duration has been exceeded; disconnect the call */
	PJ_LOG(3,(THIS_FILE, "Duration (%d seconds) has been exceeded "
		"for call %d, disconnecting the call", app_config.duration, call_id));
	entry->id = PJSUA_INVALID_ID;
	pjsua_call_hangup(call_id, 200, NULL, &msg_data_);
}


pj_status_t ice_client_init(ice_info_t *info)
{
	pjsua_transport_id transport_id = -1;
	pjsua_transport_config tcp_cfg;
	unsigned i;
	pj_pool_t *tmp_pool;
	pj_status_t status;

	/** Create pjsua **/
	status = pjsua_create();
	if (status != PJ_SUCCESS)
		return status;

	/* Create pool for application */
	app_config.pool = pjsua_pool_create("pjsua-app", 1000, 1000);
	tmp_pool = pjsua_pool_create("tmp-pjsua", 1000, 1000);

	/** Parse args **/
	//status = load_config(app_cfg.argc, app_cfg.argv, &uri_arg);
	//if (status != PJ_SUCCESS) {
	//	pj_pool_release(tmp_pool);
	//	return status;
	//}
	default_config();
	app_config.client = (socket_client*)PJ_POOL_ZALLOC_T(app_config.pool, socket_client);

	//ice_info_t info = {0};
	//pj_strcpy(info.account, "102");
	//pj_strcpy(info.passwd, "102");
	//pj_strcpy(info.server, "172.17.13.8");
	//pj_strcpy(info.realm, "172.17.13.8");

	//pj_strcpy(info.turn, "172.17.13.8:3488");
	//pj_strcpy(info.username, "username2");
	//pj_strcpy(info.password, "password2");
	set_args(info);

	/* Initialize application callbacks */
	app_config.cfg.cb.on_call_state = &on_call_state;
	//app_config.cfg.cb.on_call_media_state = &on_call_media_state;
	app_config.cfg.cb.on_incoming_call = &on_incoming_call;
	//app_config.cfg.cb.on_call_tsx_state = &on_call_tsx_state;
	//app_config.cfg.cb.on_dtmf_digit = &call_on_dtmf_callback;
	//app_config.cfg.cb.on_call_redirected = &call_on_redirected;
	app_config.cfg.cb.on_reg_state = &on_reg_state;
	//app_config.cfg.cb.on_incoming_subscribe = &on_incoming_subscribe;
	//app_config.cfg.cb.on_buddy_state = &on_buddy_state;
	//app_config.cfg.cb.on_buddy_evsub_state = &on_buddy_evsub_state;
	//app_config.cfg.cb.on_pager = &on_pager;
	//app_config.cfg.cb.on_typing = &on_typing;
	//app_config.cfg.cb.on_call_transfer_status = &on_call_transfer_status;
	//app_config.cfg.cb.on_call_replaced = &on_call_replaced;
	app_config.cfg.cb.on_nat_detect = &on_nat_detect;
	//app_config.cfg.cb.on_mwi_info = &on_mwi_info;
	//app_config.cfg.cb.on_transport_state = &on_transport_state;
	//app_config.cfg.cb.on_ice_transport_error = &on_ice_transport_error;
	//app_config.cfg.cb.on_snd_dev_operation = &on_snd_dev_operation;
	//app_config.cfg.cb.on_call_media_event = &on_call_media_event;
//#ifdef TRANSPORT_ADAPTER_SAMPLE
//	app_config.cfg.cb.on_create_media_transport = &on_create_media_transport;
	//#endif

	app_config.cfg.cb.on_ice_negotiation_success = &on_ice_negotiation_success;
	app_config.cfg.cb.on_ice_connection_success = &on_ice_connection_success;
	app_config.cfg.cb.on_ice_receive_message = &on_ice_receive_message;


	/* Initialize pjsua */
	status = pjsua_init(&app_config.cfg, &app_config.log_cfg, &app_config.media_cfg);
	if (status != PJ_SUCCESS) {
		pj_pool_release(tmp_pool);
		return status;
	}

	/* Initialize our module to handle otherwise unhandled request */
	//status = pjsip_endpt_register_module(pjsua_get_pjsip_endpt(), &mod_default_handler);
	//if (status != PJ_SUCCESS)
	//	return status;

	/* Initialize calls data */
	for (i=0; i<PJ_ARRAY_SIZE(app_config.call_data); ++i) {
		app_config.call_data[i].timer.id = PJSUA_INVALID_ID;
		app_config.call_data[i].timer.cb = &call_timeout_callback;
	}

	pj_memcpy(&tcp_cfg, &app_config.udp_cfg, sizeof(tcp_cfg));

	/* Add UDP transport unless it's disabled. */
	{
		pjsua_acc_id aid;
		pjsip_transport_type_e type = PJSIP_TRANSPORT_UDP;

		status = pjsua_transport_create(type, &app_config.udp_cfg, &transport_id);
		if (status != PJ_SUCCESS)
			goto on_error;

		/* Add local account */
		pjsua_acc_add_local(transport_id, PJ_TRUE, &aid);

		/* Adjust local account config based on pjsua app config */
		{
			pjsua_acc_config acc_cfg;
			pjsua_acc_get_config(aid, tmp_pool, &acc_cfg);

			//app_config_init_video(&acc_cfg);
			acc_cfg.rtp_cfg = app_config.rtp_cfg;
			pjsua_acc_modify(aid, &acc_cfg);
		}

		pjsua_acc_set_online_status(current_acc, PJ_TRUE);

// 		if (app_config.udp_cfg.port == 0) {
// 			pjsua_transport_info ti;
// 			pj_sockaddr_in *a;
// 
// 			pjsua_transport_get_info(transport_id, &ti);
// 			a = (pj_sockaddr_in*)&ti.local_addr;
// 
// 			tcp_cfg.port = pj_ntohs(a->sin_port);
// 		}
	}

	/* Add TCP transport unless it's disabled */
	if (!app_config.no_tcp) {
		pjsua_acc_id aid;

		status = pjsua_transport_create(PJSIP_TRANSPORT_TCP, &tcp_cfg, &transport_id);
		if (status != PJ_SUCCESS)
			goto on_error;

		/* Add local account */
		pjsua_acc_add_local(transport_id, PJ_TRUE, &aid);

		/* Adjust local account config based on pjsua app config */
		{
			pjsua_acc_config acc_cfg;
			pjsua_acc_get_config(aid, tmp_pool, &acc_cfg);

			//app_config_init_video(&acc_cfg);
			acc_cfg.rtp_cfg = app_config.rtp_cfg;
			pjsua_acc_modify(aid, &acc_cfg);
		}

		pjsua_acc_set_online_status(current_acc, PJ_TRUE);

	}

	if (transport_id == -1) {
		PJ_LOG(1,(THIS_FILE, "Error: no transport is configured"));
		status = -1;
		goto on_error;
	}

	/* Add accounts */
	for (i=0; i<app_config.acc_cnt; ++i) {
		app_config.acc_cfg[i].rtp_cfg = app_config.rtp_cfg;
		app_config.acc_cfg[i].reg_retry_interval = 300;
		app_config.acc_cfg[i].reg_first_retry_interval = 60;

		//app_config_init_video(&app_config.acc_cfg[i]);

		status = pjsua_acc_add(&app_config.acc_cfg[i], PJ_TRUE, NULL);
		if (status != PJ_SUCCESS)
			goto on_error;
		pjsua_acc_set_online_status(current_acc, PJ_TRUE);
	}

// 	/* Add buddies */
// 	for (i=0; i<app_config.buddy_cnt; ++i) {
// 		status = pjsua_buddy_add(&app_config.buddy_cfg[i], NULL);
// 		if (status != PJ_SUCCESS) {
// 			PJ_PERROR(1,(THIS_FILE, status, "Error adding buddy"));
// 			goto on_error;
// 		}
// 	}
// 
// 	/* Optionally disable some codec */
// 	for (i=0; i<app_config.codec_dis_cnt; ++i) {
// 		pjsua_codec_set_priority(&app_config.codec_dis[i], PJMEDIA_CODEC_PRIO_DISABLED);
// #if PJSUA_HAS_VIDEO
// 		pjsua_vid_codec_set_priority(&app_config.codec_dis[i],
// 			PJMEDIA_CODEC_PRIO_DISABLED);
// #endif
// 	}
// 
// 	/* Optionally set codec orders */
// 	for (i=0; i<app_config.codec_cnt; ++i) {
// 		pjsua_codec_set_priority(&app_config.codec_arg[i],
// 			(pj_uint8_t)(PJMEDIA_CODEC_PRIO_NORMAL+i+9));
// #if PJSUA_HAS_VIDEO
// 		pjsua_vid_codec_set_priority(&app_config.codec_arg[i],
// 			(pj_uint8_t)(PJMEDIA_CODEC_PRIO_NORMAL+i+9));
// #endif
// 	}

	/* Use null sound device? */
#ifndef STEREO_DEMO
	if (app_config.null_audio) {
		status = pjsua_set_null_snd_dev();
		if (status != PJ_SUCCESS)
			return status;
	}
#endif


	/* Init call setting */
	pjsua_call_setting_default(&call_opt);
	call_opt.aud_cnt = app_config.aud_cnt;
	call_opt.vid_cnt = app_config.vid.vid_cnt;

	//status = pjsua_start();
	//if (status != PJ_SUCCESS)
	//	return status;

	pj_pool_release(tmp_pool);
	return PJ_SUCCESS;

on_error:
	pj_pool_release(tmp_pool);
	ice_client_destroy();
	return status;
}

//pj_status_t app_run(void)
//{
//	pj_status_t status;
//
//	status = pjsua_start();
//
//	return status;
//}
pj_status_t ice_client_register(iclient_callback *ctx)
{
	pj_status_t status;
	socket_client *client = app_config.client;

	PJ_ASSERT_RETURN(ctx, PJ_EINVAL);

	client->ctx = ctx;
	client->cb.on_connect_success = ctx->on_connect_success;
	client->cb.on_receive_message = ctx->on_receive_message;

	status = pjsua_start();

	return status;
}

//void ice_make_connect(iclient_callback *ctx, char *uri)
void ice_make_connect(char *uri)
{
	//socket_client *client = NULL;
	pjsua_msg_data msg_data_;

	pj_assert(uri);

	//client = app_config.client;
	//client->ctx = ctx;
	//client->cb.on_connect_success = ctx->on_connect_success;
	//client->cb.on_receive_message = ctx->on_receive_message;

	pj_str_t tmp = pj_str(uri);

	pjsua_msg_data_init(&msg_data_);
	//TEST_MULTIPART(&msg_data_);
	pjsua_call_make_call(current_acc, &tmp, &call_opt, NULL, &msg_data_, &current_call);
}

pj_status_t ice_packet_send(const void *pkt, pj_size_t size)
{
	pj_status_t status = -1;
	socket_client *client = (socket_client*)app_config.client;

	if (pkt && client && client->tp)
		status = pjmedia_transport_send_rtp(client->tp, pkt, size);

	return status;
}

pj_status_t ice_client_destroy(void)
{
	pj_status_t status = PJ_SUCCESS;

	pj_pool_safe_release(&app_config.pool);

	status = pjsua_destroy();

	/* Reset config */
	pj_bzero(&app_config, sizeof(app_config));

	return status;
}


void ice_client_status(void)
{
	keystroke_help();
}
