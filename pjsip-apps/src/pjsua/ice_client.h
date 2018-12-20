/* 
* Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
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
#ifndef __ICE_CLIENT_H__
#define __ICE_CLIENT_H__

#include <pjsua-lib/pjsua.h>

PJ_BEGIN_DECL

#define current_acc	pjsua_acc_get_default()

#define PJSUA_APP_NO_LIMIT_DURATION	(int)0x7FFFFFFF
#define PJSUA_APP_MAX_AVI		4
#define PJSUA_APP_NO_NB			-2

typedef struct input_result
{
	int	  nb_result;
	char *uri_result;
} input_result;

/* Call specific data */
typedef struct app_call_data
{
	pj_timer_entry	    timer;
	pj_bool_t		    ringback_on;
	pj_bool_t		    ring_on;
} app_call_data;

/* Video settings */
typedef struct app_vid
{
	unsigned		    vid_cnt;
	int			    vcapture_dev;
	int			    vrender_dev;
	pj_bool_t		    in_auto_show;
	pj_bool_t		    out_auto_transmit;
} app_vid;

//typedef struct sip_context
//{
//	void	*tp;
//	int		connected;
//
//} sip_context_t;

typedef struct ice_info_s
{
	char	account[32];	// 102
	char	passwd[32];		// 102
	char	server[32];	// "172.17.13.8"
	char	realm[32];	// "172.17.13.8"

	char	turn[32];	// "172.17.13.8:3488"
	char	turn_port[16];	// "3488"
	char	username[32];	// username2
	char	password[32];	// password2

	int		conn_type;
} ice_info_t;


typedef struct ice_client_param
{
	int			call_id;
	int			status;

} ice_client_param;

typedef struct iclient_callback
{
	void (*on_register_status)(void *ctx, void *param);

	void (*on_connect_success)(void *ctx, void *param);

	void (*on_connect_failure)(void *ctx, void *param);

	void (*on_sock_disconnect)(void *ctx, void *param);

	void (*on_socket_clearing)(void *ctx, void *param);

	void (*on_socket_writable)(void *ctx, void *param);

	void (*on_receive_message)(void *ctx, void *pkt, pj_ssize_t bytes_read);
} iclient_callback;

/* Pjsua application data */
typedef struct pjsua_app_config
{
	//sip_context_t		sip_ctx;
	void				*client;

	pjsua_config	    cfg;
	pjsua_logging_config    log_cfg;
	pjsua_media_config	    media_cfg;
	pj_bool_t		    no_refersub;
	pj_bool_t		    ipv6;
	pj_bool_t		    enable_qos;
	pj_bool_t		    no_tcp;
	pj_bool_t		    no_udp;
	pj_bool_t		    use_tls;
	pjsua_transport_config  udp_cfg;
	pjsua_transport_config  rtp_cfg;
	pjsip_redirect_op	    redir_op;

	unsigned		    acc_cnt;
	pjsua_acc_config	    acc_cfg[PJSUA_MAX_ACC];

	unsigned		    buddy_cnt;
	pjsua_buddy_config	    buddy_cfg[PJSUA_MAX_BUDDIES];

	app_call_data	    call_data[PJSUA_MAX_CALLS];

	pj_pool_t		   *pool;
	/* Compatibility with older pjsua */

	unsigned		    codec_cnt;
	pj_str_t		    codec_arg[32];
	unsigned		    codec_dis_cnt;
	pj_str_t                codec_dis[32];
	pj_bool_t		    null_audio;
	unsigned		    wav_count;
	pj_str_t		    wav_files[32];
	unsigned		    tone_count;
	pjmedia_tone_desc	    tones[32];
	pjsua_conf_port_id	    tone_slots[32];
	pjsua_player_id	    wav_id;
	pjsua_conf_port_id	    wav_port;
	pj_bool_t		    auto_play;
	pj_bool_t		    auto_play_hangup;
	pj_timer_entry	    auto_hangup_timer;
	pj_bool_t		    auto_loop;
	pj_bool_t		    auto_conf;
	pj_str_t		    rec_file;
	pj_bool_t		    auto_rec;
	pjsua_recorder_id	    rec_id;
	pjsua_conf_port_id	    rec_port;
	unsigned		    auto_answer;
	unsigned		    duration;

#ifdef STEREO_DEMO
	pjmedia_snd_port	   *snd;
	pjmedia_port	   *sc, *sc_ch1;
	pjsua_conf_port_id	    sc_ch1_slot;
#endif

	float		    mic_level, speaker_level;

	int			    capture_dev, playback_dev;
	unsigned		    capture_lat, playback_lat;

	pj_bool_t		    no_tones;
	int			    ringback_slot;
	int			    ringback_cnt;
	pjmedia_port	   *ringback_port;
	int			    ring_slot;
	int			    ring_cnt;
	pjmedia_port	   *ring_port;

	app_vid		    vid;
	unsigned		    aud_cnt;

	/* AVI to play */
	unsigned                avi_cnt;
	struct {
		pj_str_t		path;
		pjmedia_vid_dev_index	dev_id;
		pjsua_conf_port_id	slot;
	} avi[PJSUA_APP_MAX_AVI];
	pj_bool_t               avi_auto_play;
	int			    avi_def_idx;

} pjsua_app_config;

/** Extern variable declaration **/
//extern pjsua_call_id	    current_call;
//extern pjsua_app_config	    app_config;
//extern pjsua_call_setting   call_opt;


pj_status_t ice_thread_register(const char *thread_name);

pj_status_t ice_client_init(ice_info_t *info);

pj_status_t ice_client_register(iclient_callback *ctx);

pj_status_t ice_make_connect(char *uri);

void ice_client_disconnect(void);

pj_status_t ice_packet_send(const void *pkt, pj_size_t size);

pj_status_t ice_client_destroy(void);

void ice_client_status(void);

pj_pool_t* ice_pool_get(void);

pj_pool_t* ice_pool_create(const char *name, pj_size_t init_size, pj_size_t increment);

PJ_END_DECL

#endif	/* __ICE_CLIENT_H__ */

