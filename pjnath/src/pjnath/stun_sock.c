/* $Id: stun_sock.c 5678 2017-11-01 04:55:29Z riza $ */
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
#include <pjnath/stun_sock.h>
#include <pjnath/errno.h>
#include <pjnath/stun_transaction.h>
#include <pjnath/stun_session.h>
#include <pjlib-util/srv_resolver.h>
#include <pj/activesock.h>
#include <pj/addr_resolv.h>
#include <pj/array.h>
#include <pj/assert.h>
#include <pj/ip_helper.h>
#include <pj/log.h>
#include <pj/os.h>
#include <pj/pool.h>
#include <pj/rand.h>

#if 1
#  define TRACE_(x)	PJ_LOG(5,x)
#else
#  define TRACE_(x)
#endif

enum { MAX_BIND_RETRY = 100 };

struct pj_stun_sock
{
    char		*obj_name;	/* Log identification	    */
    pj_pool_t		*pool;		/* Pool			    */
    void		*user_data;	/* Application user data    */
    pj_bool_t		 is_destroying; /* Destroy already called   */
    int			 af;		/* Address family	    */
    pj_stun_config	 stun_cfg;	/* STUN config (ioqueue etc)*/
    pj_stun_sock_cb	 cb;		/* Application callbacks    */

	// add
	pj_stun_sock_cfg		cfg;
	pj_bool_t				is_server;	 /* is server flag, it's for LAN tcp mode    */
	pj_activesock_t			*asock;	 /* Active socket object for server    */
	pj_ioqueue_op_key_t		op_key;

	pj_uint8_t				tx_pkt[PJ_TURN_MAX_PKT_LEN];

	int			 ka_interval;	/* Keep alive interval	    */
	pj_timer_entry	 ka_timer;	/* Keep alive timer.	    */

    pj_sockaddr		 srv_addr;	/* Resolved server addr	    */
    pj_sockaddr		 mapped_addr;	/* Our public address	    */

    pj_dns_srv_async_query *q;		/* Pending DNS query	    */
    pj_sock_t		 sock_fd;	/* Socket descriptor	    */
    pj_activesock_t	*active_sock;	/* Active socket object	    */
    pj_ioqueue_op_key_t	 send_key;	/* Default send key for app */
    pj_ioqueue_op_key_t	 int_send_key;	/* Send key for internal    */

    pj_uint16_t		 tsx_id[6];	/* .. to match STUN msg	    */
    pj_stun_session	*stun_sess;	/* STUN session		    */
    pj_grp_lock_t	*grp_lock;	/* Session group lock	    */
};

typedef struct pj_stun_header_data
{
	pj_uint16_t number;		/**< Channel number.    */
	pj_uint16_t length;		/**< Payload length.	*/
} pj_stun_header_data;


/* 
 * Prototypes for static functions 
 */

/* Destructor for group lock */
static void stun_sock_destructor(void *obj);

/* This callback is called by the STUN session to send packet */
static pj_status_t sess_on_send_msg(pj_stun_session *sess,
				    void *token,
				    const void *pkt,
				    pj_size_t pkt_size,
				    const pj_sockaddr_t *dst_addr,
				    unsigned addr_len);

/* This callback is called by the STUN session when outgoing transaction 
 * is complete
 */
static void sess_on_request_complete(pj_stun_session *sess,
				     pj_status_t status,
				     void *token,
				     pj_stun_tx_data *tdata,
				     const pj_stun_msg *response,
				     const pj_sockaddr_t *src_addr,
				     unsigned src_addr_len);
/* DNS resolver callback */
static void dns_srv_resolver_cb(void *user_data,
				pj_status_t status,
				const pj_dns_srv_record *rec);

/* Start sending STUN Binding request */
static pj_status_t get_mapped_addr(pj_stun_sock *stun_sock);

/* Callback from active socket when incoming packet is received */
static pj_bool_t on_data_recvfrom(pj_activesock_t *asock,
				  void *data,
				  pj_size_t size,
				  const pj_sockaddr_t *src_addr,
				  int addr_len,
				  pj_status_t status);

/* Callback from active socket about send status */
static pj_bool_t on_data_sent(pj_activesock_t *asock,
			      pj_ioqueue_op_key_t *send_key,
			      pj_ssize_t sent);

static pj_bool_t on_data_read(pj_activesock_t *asock,
							  void *data,
							  pj_size_t size,
							  pj_status_t status,
							  pj_size_t *remainder);

/* Schedule keep-alive timer */
static void start_ka_timer(pj_stun_sock *stun_sock);

/* Keep-alive timer callback */
static void ka_timer_cb(pj_timer_heap_t *th, pj_timer_entry *te);

#define INTERNAL_MSG_TOKEN  (void*)(pj_ssize_t)1


/*
 * Retrieve the name representing the specified operation.
 */
PJ_DEF(const char*) pj_stun_sock_op_name(pj_stun_sock_op op)
{
    const char *names[] = {
	"?",
	"DNS resolution",
	"STUN Binding request",
	"Keep-alive",
	"Mapped addr. changed"
    };

    return op < PJ_ARRAY_SIZE(names) ? names[op] : "???";
}


/*
 * Initialize the STUN transport setting with its default values.
 */
PJ_DEF(void) pj_stun_sock_cfg_default(pj_stun_sock_cfg *cfg)
{
    pj_bzero(cfg, sizeof(*cfg));
    cfg->max_pkt_size = PJ_STUN_SOCK_PKT_LEN;
    cfg->async_cnt = 1;
    cfg->ka_interval = PJ_STUN_KEEP_ALIVE_SEC;
    cfg->qos_type = PJ_QOS_TYPE_BEST_EFFORT;
    cfg->qos_ignore_error = PJ_TRUE;
}


/* Check that configuration setting is valid */
static pj_bool_t pj_stun_sock_cfg_is_valid(const pj_stun_sock_cfg *cfg)
{
    return cfg->max_pkt_size > 1 && cfg->async_cnt >= 1;
}

/*
 * Notification when outgoing TCP socket has been connected.
 */
static pj_bool_t on_connect_complete(pj_activesock_t *asock,
									 pj_status_t status)
{
	pj_stun_sock *stcp_sock;

	stcp_sock = (pj_stun_sock*) pj_activesock_get_user_data(asock);
	if (!stcp_sock)
		return PJ_FALSE;

	pj_grp_lock_acquire(stcp_sock->grp_lock);

	if (status != PJ_SUCCESS) {
		//sess_fail(stcp_sock, "TCP connect() error", status);
		PJ_PERROR(4,(stcp_sock->obj_name, status, "TCP connect() error"));
		if (stcp_sock->cb.on_status)
			(*stcp_sock->cb.on_status)(stcp_sock, PJ_STUN_SOCK_TCP_CONN_COMPLETE, status);

		pj_grp_lock_release(stcp_sock->grp_lock);
		pj_stun_sock_destroy(stcp_sock);
		return PJ_FALSE;
	}

	//if (stcp_sock->conn_type != PJ_TURN_TP_UDP) {
	PJ_LOG(4,(stcp_sock->obj_name, "================================================="));
	PJ_LOG(4,(stcp_sock->obj_name, "================= TCP connected ================="));
	//}

	/* Kick start pending read operation */
	status = pj_activesock_start_read(asock, stcp_sock->pool, stcp_sock->cfg.max_pkt_size, 0);

	/* Init send_key */
	pj_ioqueue_op_key_init(&stcp_sock->send_key, sizeof(stcp_sock->send_key));

	if (stcp_sock->cb.on_status)
		(*stcp_sock->cb.on_status)(stcp_sock, PJ_STUN_SOCK_TCP_CONN_COMPLETE, PJ_SUCCESS);

	pj_grp_lock_release(stcp_sock->grp_lock);
	return PJ_TRUE;
}

static pj_bool_t on_accept_complete(pj_activesock_t *asock,
									 pj_sock_t newsock,
									 const pj_sockaddr_t *src_addr,
									 int src_addr_len,
									 pj_status_t status)
{
	pj_stun_sock *stcp_sock;
	pj_pool_t *pool;
	//lan_sock_sess *sess = NULL;
	pj_activesock_cb asock_cb;
	int addr_len;
	pj_sockaddr local_addr;
	char addr[PJ_INET6_ADDRSTRLEN+10];

	stcp_sock = (pj_stun_sock*) pj_activesock_get_user_data(asock);
	if (!stcp_sock)
		return PJ_FALSE;

	pj_grp_lock_acquire(stcp_sock->grp_lock);

	pool = stcp_sock->pool;

	addr_len = sizeof(local_addr);
	status = pj_sock_getsockname(newsock, &local_addr, &addr_len);	

	PJ_LOG(4,(stcp_sock->obj_name, 
		"TCP server %s:%d: got incoming TCP connection from %s, sock=%d",
		pj_inet_ntoa(*(pj_in_addr*)pj_sockaddr_get_addr(&local_addr)),
		pj_sockaddr_get_port(&local_addr),
		pj_sockaddr_print(src_addr, addr, sizeof(addr), 3), newsock));

	if (status != PJ_SUCCESS && status != PJ_EPENDING) {
		PJ_PERROR(4, (stcp_sock->obj_name, status, "Error TCP on data accept() %d", status));
		//if (status == PJ_ESOCKETSTOP)
		//	telnet_restart(fe);

		if (stcp_sock->cb.on_status)
			(*stcp_sock->cb.on_status)(stcp_sock, PJ_STUN_SOCK_TCP_CONN_COMPLETE, status);

		pj_grp_lock_release(stcp_sock->grp_lock);
		pj_stun_sock_destroy(stcp_sock);

		return status;
	}

	pj_bzero(&asock_cb, sizeof(asock_cb));
	asock_cb.on_data_read = &on_data_read;
	//asock_cb.on_data_sent = &telnet_sess_on_data_sent;
	asock_cb.on_data_sent = &on_data_sent;
	status = pj_activesock_create(pool, newsock, 
		pj_SOCK_STREAM(), NULL, stcp_sock->stun_cfg.ioqueue,	//...
		&asock_cb, stcp_sock, &stcp_sock->asock);
	if (status != PJ_SUCCESS)
		goto on_error;
	
	PJ_LOG(4,(stcp_sock->obj_name, "============== [server]TCP connected ===================="));

	/* Start reading for input from the new telnet session */
	status = pj_activesock_start_read(stcp_sock->asock, pool, stcp_sock->cfg.max_pkt_size, 0);
	if (status != PJ_SUCCESS) {
		PJ_PERROR(4, (stcp_sock->obj_name, status, "Failure reading active socket at accept"));
		goto on_error;
	}

	pj_ioqueue_op_key_init(&stcp_sock->op_key, sizeof(stcp_sock->op_key));

	stcp_sock->is_server = 1;

	if (stcp_sock->cb.on_status)
		(*stcp_sock->cb.on_status)(stcp_sock, PJ_STUN_SOCK_TCP_CONN_COMPLETE, PJ_SUCCESS);

	pj_grp_lock_release(stcp_sock->grp_lock);
	return PJ_SUCCESS;

on_error:
	if (stcp_sock->asock)
		pj_activesock_close(stcp_sock->asock);
	else
		pj_sock_close(newsock);

	pj_grp_lock_release(stcp_sock->grp_lock);

	//if (sess->smutex)
	//	pj_mutex_destroy(sess->smutex);

	//pj_pool_release(pool);

	return status;
}

static pj_uint16_t GETVAL16H(const pj_uint8_t *buf, unsigned pos)
{
	return (pj_uint16_t) ((buf[pos + 0] << 8) | (buf[pos + 1] << 0));
}

/* Quick check to determine if there is enough packet to process in the
* incoming buffer. Return the packet length, or zero if there's no packet.
*/
static unsigned has_packet(pj_stun_sock *stcp_sock, const void *buf, pj_size_t bufsize)
{
	//pj_bool_t is_stun;

	///* Quickly check if this is STUN message, by checking the first two bits and
	//* size field which must be multiple of 4 bytes
	//*/
	//is_stun = ((((pj_uint8_t*)buf)[0] & 0xC0) == 0) &&
	//	((GETVAL16H((const pj_uint8_t*)buf, 2) & 0x03)==0);

	//if (is_stun) {
	//	pj_size_t msg_len = GETVAL16H((const pj_uint8_t*)buf, 2);
	//	return (unsigned)((msg_len+20 <= bufsize) ? msg_len+20 : 0);
	//} else {
	//	/* This must be ChannelData. */
	//	pj_turn_channel_data cd;

	//	if (bufsize < 4)
	//		return 0;

	//	/* Decode ChannelData packet */
	//	pj_memcpy(&cd, buf, sizeof(pj_turn_channel_data));
	//	cd.length = pj_ntohs(cd.length);

	//	if (bufsize >= cd.length+sizeof(cd)) 
	//		return (cd.length+sizeof(cd)+3) & (~3);
	//	else
	//		return 0;
	//}

	pj_stun_header_data hd;

	if (bufsize < 4)
		return 0;

	/* Decode Data packet */
	pj_memcpy(&hd, buf, sizeof(pj_stun_header_data));
	hd.length = pj_ntohs(hd.length);

	if (bufsize >= hd.length+sizeof(hd)) 
		return (hd.length+sizeof(hd)+3) & (~3);
	else
		return 0;
}

static int stun_on_rx_pkt(pj_stun_sock *tcp_sock, void *pkt, pj_size_t pkt_len, pj_size_t *parsed_len)
{
	pj_status_t status;
	pj_stun_header_data hd;

	if (pkt_len < 4) {
		if (parsed_len) *parsed_len = 0;
		return PJ_ETOOSMALL;
	}

	//pj_bool_t is_stun = ((((pj_uint8_t*)pkt)[0] & 0xC0) == 0);

	//if (is_stun) {
	//	/* This looks like STUN, give it to the STUN session */
	//	unsigned options;

	//	options = PJ_STUN_CHECK_PACKET | PJ_STUN_NO_FINGERPRINT_CHECK;
	//	//if (is_datagram)
	//	//	options |= PJ_STUN_IS_DATAGRAM;
	//	//status=pj_stun_session_on_rx_pkt(sess->stun, pkt, pkt_len,
	//	//	options, NULL, parsed_len,
	//	//	sess->srv_addr,
	//	//	pj_sockaddr_get_len(sess->srv_addr));

	//	PJ_LOG(4, (tcp_sock->obj_name, "=============== is stun msg in tcp rx pkt ============="));

	//}

	/* Decode Data packet */
	pj_memcpy(&hd, pkt, sizeof(pj_stun_header_data));
	hd.number = pj_ntohs(hd.number);
	hd.length = pj_ntohs(hd.length);

	/* Check that size is sane */
	if (pkt_len < hd.length+sizeof(hd)) {
		if (parsed_len) {
			/* Insufficient fragment */
			*parsed_len = 0;
		}
		status = PJ_ETOOSMALL;
		goto on_return;
	} else {
		if (parsed_len) {
			/* Apply padding too */
			//*parsed_len = ((hd.length + 3) & (~3)) + sizeof(hd);
			*parsed_len = ((hd.length + sizeof(hd) + 3) & (~3));
		}
	}

	if (tcp_sock->cb.on_rx_data) {
		(*tcp_sock->cb.on_rx_data)(tcp_sock, ((pj_uint8_t*)pkt)+sizeof(hd), hd.length, NULL, 0);
	}

on_return:
	//pj_grp_lock_release(sess->grp_lock);
	return status;
}

/*
 * Notification from ioqueue when incoming TCP packet is received.
 */
static pj_bool_t on_data_read(pj_activesock_t *asock,
							  void *data,
							  pj_size_t size,
							  pj_status_t status,
							  pj_size_t *remainder)
{
	pj_stun_sock *stcp_sock;
	pj_bool_t ret = PJ_TRUE;

	stcp_sock = (pj_stun_sock*) pj_activesock_get_user_data(asock);
	pj_grp_lock_acquire(stcp_sock->grp_lock);

	if (status == PJ_SUCCESS && !stcp_sock->is_destroying) {
		/* Report incoming packet to TURN session, repeat while we have
		* "packet" in the buffer (required for stream-oriented transports)
		*/
		unsigned pkt_len;

		//PJ_LOG(5,(stcp_sock->pool->obj_name, 
		//	  "Incoming data, %lu bytes total buffer", size));

		*remainder = size;

		while ((pkt_len=has_packet(stcp_sock, data, size)) != 0) {
			pj_size_t parsed_len;
			//const pj_uint8_t *pkt = (const pj_uint8_t*)data;

			//PJ_LOG(5,(stcp_sock->pool->obj_name, 
			//	      "Packet start: %02X %02X %02X %02X", 
			//	      pkt[0], pkt[1], pkt[2], pkt[3]));

			//PJ_LOG(5,(stcp_sock->pool->obj_name, 
			//	      "Processing %lu bytes packet of %lu bytes total buffer",
			//	      pkt_len, size));

			parsed_len = (unsigned)size;
			//pj_turn_session_on_rx_pkt(stcp_sock->sess, data,  size, &parsed_len);
			stun_on_rx_pkt(stcp_sock, data,  size, &parsed_len);

			/* parsed_len may be zero if we have parsing error, so use our
			* previous calculation to exhaust the bad packet.
			*/
			if (parsed_len == 0)
				parsed_len = pkt_len;

			if (parsed_len < (unsigned)size) {
				*remainder = size - parsed_len;
				pj_memmove(data, ((char*)data)+parsed_len, *remainder);
			} else {
				*remainder = 0;
			}
			size = *remainder;

			//PJ_LOG(5,(stcp_sock->pool->obj_name, 
			//	      "Buffer size now %lu bytes", size));
		}
	} else if (status != PJ_SUCCESS) {
		//sess_fail(stcp_sock, "TCP connection closed", status);
		pj_perror(3, stcp_sock->pool->obj_name, status, "TCP connection closed");
		PJ_PERROR(3,(stcp_sock->obj_name, status, "TCP connection closed"));

		if (stcp_sock->cb.on_status)
			(*stcp_sock->cb.on_status)(stcp_sock, PJ_STUN_SOCK_TCP_DISCONNECT, status);

		ret = PJ_FALSE;
		goto on_return;
	}

on_return:
	pj_grp_lock_release(stcp_sock->grp_lock);

	return ret;
}

/*
 * Create the STUN transport using the specified configuration.
 */
PJ_DEF(pj_status_t) pj_stun_tcp_sock_create( pj_stun_config *stun_cfg,
										const pj_sockaddr_t *dst_addr,
										pj_uint16_t lport,
										int af,
										const pj_stun_sock_cb *cb,
										const pj_stun_sock_cfg *cfg,
										void *user_data,
										pj_stun_sock **p_stun_sock)
{
	pj_pool_t *pool;
	pj_stun_sock *stcp_sock;
	pj_stun_sock_cfg default_cfg;
	//pj_sockaddr bound_addr;
	pj_status_t status;
	int opt = 1;

	PJ_ASSERT_RETURN(stun_cfg && cb && p_stun_sock, PJ_EINVAL);
	PJ_ASSERT_RETURN(af==pj_AF_INET()||af==pj_AF_INET6(), PJ_EAFNOTSUP);
	PJ_ASSERT_RETURN(!cfg || pj_stun_sock_cfg_is_valid(cfg), PJ_EINVAL);
	PJ_ASSERT_RETURN(cb->on_status, PJ_EINVAL);

	status = pj_stun_config_check_valid(stun_cfg);
	if (status != PJ_SUCCESS) {
		PJ_LOG(4, (stcp_sock->pool->obj_name, "=====111111 %d", status));

		return status;
	}

	if (cfg == NULL) {
		pj_stun_sock_cfg_default(&default_cfg);
		cfg = &default_cfg;
	}

	/* Create structure */
	pool = pj_pool_create(stun_cfg->pf, "stcptp%p", 256, 512, NULL);
	stcp_sock = PJ_POOL_ZALLOC_T(pool, pj_stun_sock);
	stcp_sock->pool = pool;
	stcp_sock->obj_name = pool->obj_name;
	stcp_sock->user_data = user_data;
	stcp_sock->af = af;
	stcp_sock->sock_fd = PJ_INVALID_SOCKET;
	pj_memcpy(&stcp_sock->stun_cfg, stun_cfg, sizeof(*stun_cfg));
	pj_memcpy(&stcp_sock->cb, cb, sizeof(*cb));
	/* Copy setting (QoS parameters etc */
	pj_memcpy(&stcp_sock->cfg, cfg, sizeof(*cfg));

	//stcp_sock->ka_interval = cfg->ka_interval;
	//if (stcp_sock->ka_interval == 0)
	//	stcp_sock->ka_interval = PJ_STUN_KEEP_ALIVE_SEC;

	/*if (cfg->grp_lock) {
		stcp_sock->grp_lock = cfg->grp_lock;
	} else*/ {
		status = pj_grp_lock_create(pool, NULL, &stcp_sock->grp_lock);
		if (status != PJ_SUCCESS) {
			PJ_LOG(4, (stcp_sock->pool->obj_name, "=====22222222 %d", status));
			pj_pool_release(pool);
			return status;
		}
	}

	pj_grp_lock_add_ref(stcp_sock->grp_lock);
	pj_grp_lock_add_handler(stcp_sock->grp_lock, pool, stcp_sock, &stun_sock_destructor);

	/* Create socket and bind socket */
	status = pj_sock_socket(af, pj_SOCK_STREAM(), 0, &stcp_sock->sock_fd);
	if (status != PJ_SUCCESS) {
		PJ_LOG(4, (stcp_sock->pool->obj_name, "=====333333 %d", status));
		goto on_error;
	}

	status = pj_sock_setsockopt(stcp_sock->sock_fd, pj_SOL_SOCKET(), pj_SO_REUSEADDR(), &opt, sizeof(opt));	
	if (status != PJ_SUCCESS) {
		PJ_LOG(4, (stcp_sock->pool->obj_name, "=====4444444 %d", status));
		goto on_error;
	}
	//status = pj_sock_setsockopt(stcp_sock->sock_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
	//if (status != PJ_SUCCESS)
	//	goto on_error;

	/* Apply QoS, if specified */
	status = pj_sock_apply_qos2(stcp_sock->sock_fd, cfg->qos_type,
		&cfg->qos_params, 2, stcp_sock->obj_name, NULL);
	if (status != PJ_SUCCESS && !cfg->qos_ignore_error) {
		PJ_LOG(4, (stcp_sock->pool->obj_name, "=====555555 %d", status));
		goto on_error;
	}

	/* Apply socket buffer size */
	if (cfg->so_rcvbuf_size > 0) {
		unsigned sobuf_size = cfg->so_rcvbuf_size;
		status = pj_sock_setsockopt_sobuf(stcp_sock->sock_fd, pj_SO_RCVBUF(), PJ_TRUE, &sobuf_size);
		if (status != PJ_SUCCESS) {
			pj_perror(3, stcp_sock->obj_name, status, "Failed setting SO_RCVBUF");
		} else {
			if (sobuf_size < cfg->so_rcvbuf_size) {
				PJ_LOG(4, (stcp_sock->obj_name, 
					"Warning! Cannot set SO_RCVBUF as configured, "
					"now=%d, configured=%d",
					sobuf_size, cfg->so_rcvbuf_size));
			} else {
				PJ_LOG(5, (stcp_sock->obj_name, "SO_RCVBUF set to %d", sobuf_size));
			}
		}
	}
	if (cfg->so_sndbuf_size > 0) {
		unsigned sobuf_size = cfg->so_sndbuf_size;
		status = pj_sock_setsockopt_sobuf(stcp_sock->sock_fd, pj_SO_SNDBUF(), PJ_TRUE, &sobuf_size);
		if (status != PJ_SUCCESS) {
			pj_perror(3, stcp_sock->obj_name, status, "Failed setting SO_SNDBUF");
		} else {
			if (sobuf_size < cfg->so_sndbuf_size) {
				PJ_LOG(4, (stcp_sock->obj_name, 
					"Warning! Cannot set SO_SNDBUF as configured, "
					"now=%d, configured=%d",
					sobuf_size, cfg->so_sndbuf_size));
			} else {
				PJ_LOG(5, (stcp_sock->obj_name, "SO_SNDBUF set to %d", sobuf_size));
			}
		}
	}

	/* Bind socket */
	int addr_len;
	pj_sockaddr bind_addr;

	pj_sockaddr_init(af, &bind_addr, NULL, lport);
	addr_len = pj_sockaddr_get_len(&bind_addr);
	status = pj_sock_bind(stcp_sock->sock_fd, &bind_addr, addr_len);
	if (status != PJ_SUCCESS) {
		PJ_LOG(4, (stcp_sock->pool->obj_name, "======= pj_sock_bind [%d] error: %d", lport, status));
		goto on_error;
	}


	if (dst_addr == NULL)
	{
		pj_activesock_cfg activesock_cfg;
		pj_activesock_cb activesock_cb;

		pj_activesock_cfg_default(&activesock_cfg);
		activesock_cfg.grp_lock = stcp_sock->grp_lock;
		activesock_cfg.async_cnt = cfg->async_cnt;
		activesock_cfg.concurrency = 0;

		PJ_LOG(4, (stcp_sock->pool->obj_name, "Start listen on port %d", lport));

		status = pj_sock_listen(stcp_sock->sock_fd, 4);
		if (status != PJ_SUCCESS) {
			PJ_LOG(4, (stcp_sock->pool->obj_name, "=====77777777 %d", status));
			goto on_error;
		}
		/* Create the active socket */
		pj_bzero(&activesock_cb, sizeof(activesock_cb));
		//activesock_cb.on_data_read = &on_data_read;
		//activesock_cb.on_connect_complete = &on_connect_complete;
		activesock_cb.on_accept_complete2 = on_accept_complete;
		status = pj_activesock_create(pool, stcp_sock->sock_fd, 
			pj_SOCK_STREAM(), 
			&activesock_cfg, stun_cfg->ioqueue,
			&activesock_cb, stcp_sock,
			&stcp_sock->active_sock);
		if (status != PJ_SUCCESS) {
			PJ_LOG(4, (stcp_sock->pool->obj_name, "=====888888 %d", status));
			goto on_error;
		}

		status = pj_activesock_start_accept(stcp_sock->active_sock, pool);
		if (status != PJ_SUCCESS) {
			PJ_LOG(4, (stcp_sock->pool->obj_name, "=====9999999 %d", status));
			goto on_error;
		}

		PJ_LOG(4, (stcp_sock->pool->obj_name, "Start accept pass on port %d", lport));
	}
	else
	/* Init active socket configuration */
	{
		//pj_uint16_t dst_port;
		//dst_port = pj_sockaddr_get_port(dst_addr);
		char addrtxt[PJ_INET6_ADDRSTRLEN+8];

		pj_activesock_cfg activesock_cfg;
		pj_activesock_cb activesock_cb;

		pj_activesock_cfg_default(&activesock_cfg);
		activesock_cfg.grp_lock = stcp_sock->grp_lock;
		activesock_cfg.async_cnt = cfg->async_cnt;
		activesock_cfg.concurrency = 0;

		/* Create the active socket */
		pj_bzero(&activesock_cb, sizeof(activesock_cb));
		//activesock_cb.on_data_recvfrom = &on_data_recvfrom;
		activesock_cb.on_data_sent = &on_data_sent;
		activesock_cb.on_data_read = &on_data_read;
		activesock_cb.on_connect_complete = &on_connect_complete;
		status = pj_activesock_create(pool, stcp_sock->sock_fd, 
			pj_SOCK_STREAM(), 
			&activesock_cfg, stun_cfg->ioqueue,
			&activesock_cb, stcp_sock,
			&stcp_sock->active_sock);
		if (status != PJ_SUCCESS) {
			PJ_LOG(4, (stcp_sock->pool->obj_name, "=====11000000000 %d", status));
			goto on_error;
		}

		PJ_ASSERT_RETURN(dst_addr, PJ_EINVAL);

		PJ_LOG(4, (stcp_sock->pool->obj_name, "Connecting to %s", 
			pj_sockaddr_print(dst_addr, addrtxt, sizeof(addrtxt), 3)));


		///* Start asynchronous read operations */
		//status = pj_activesock_start_recvfrom(stcp_sock->active_sock, pool,
		//	cfg->max_pkt_size, 0);
		//if (status != PJ_SUCCESS)
		//	goto on_error;

		status = pj_activesock_start_connect(
			stcp_sock->active_sock, 
			stcp_sock->pool,
			dst_addr, 
			pj_sockaddr_get_len(dst_addr));

		if (status == PJ_SUCCESS) {
			on_connect_complete(stcp_sock->active_sock, PJ_SUCCESS);
		} else if (status != PJ_EPENDING) {
			pj_perror(3, stcp_sock->pool->obj_name, status, "Failed to connect to %s",
				pj_sockaddr_print(dst_addr, addrtxt, sizeof(addrtxt), 3));
			PJ_LOG(4, (stcp_sock->pool->obj_name, "=====11000000001 %d", status));
			goto on_error;
		}

		/* Init send keys */
		//pj_ioqueue_op_key_init(&stcp_sock->send_key, sizeof(stcp_sock->send_key));
		//pj_ioqueue_op_key_init(&stcp_sock->int_send_key, sizeof(stcp_sock->int_send_key));
	}

	///* Create STUN session */
	//{
	//	pj_stun_session_cb sess_cb;

	//	pj_bzero(&sess_cb, sizeof(sess_cb));
	//	sess_cb.on_request_complete = &sess_on_request_complete;
	//	sess_cb.on_send_msg = &sess_on_send_msg;
	//	status = pj_stun_session_create(&stcp_sock->stun_cfg, 
	//		stcp_sock->obj_name,
	//		&sess_cb, PJ_FALSE, 
	//		stcp_sock->grp_lock,
	//		&stcp_sock->stun_sess);
	//	if (status != PJ_SUCCESS)
	//		goto on_error;
	//}

	///* Associate us with the STUN session */
	//pj_stun_session_set_user_data(stcp_sock->stun_sess, stcp_sock);

	///* Initialize random numbers to be used as STUN transaction ID for
	//* outgoing Binding request. We use the 80bit number to distinguish
	//* STUN messages we sent with STUN messages that the application sends.
	//* The last 16bit value in the array is a counter.
	//*/
	//for (i=0; i<PJ_ARRAY_SIZE(stcp_sock->tsx_id); ++i) {
	//	stcp_sock->tsx_id[i] = (pj_uint16_t) pj_rand();
	//}
	//stcp_sock->tsx_id[5] = 0;


	///* Init timer entry */
	//stcp_sock->ka_timer.cb = &ka_timer_cb;
	//stcp_sock->ka_timer.user_data = stcp_sock;

	/* Done */
	*p_stun_sock = stcp_sock;
	return PJ_SUCCESS;

on_error:
	PJ_LOG(3, (stcp_sock->pool->obj_name, "tcp_sock_create error status %d", status));
	pj_stun_sock_destroy(stcp_sock);
	return status;
}

PJ_DEF(pj_status_t) pj_stun_tcp_sock_reconnect(pj_stun_sock *stcp_sock,
											const pj_sockaddr_t *dst_addr)
{
	pj_status_t status;
	char addrtxt[PJ_INET6_ADDRSTRLEN+8];
	//pj_pool_t *pool;
	//pj_stun_sock_cfg default_cfg;
	////pj_sockaddr bound_addr;
	//unsigned i;
	//int opt = 1;

	PJ_ASSERT_RETURN(stcp_sock, PJ_EINVAL);

	PJ_LOG(4, (stcp_sock->pool->obj_name, "Re-Connecting to %s", 
		pj_sockaddr_print(dst_addr, addrtxt, sizeof(addrtxt), 3)));

	status = pj_activesock_start_connect(
		stcp_sock->active_sock, 
		stcp_sock->pool,
		dst_addr, 
		pj_sockaddr_get_len(dst_addr));

	if (status == PJ_SUCCESS) {
		on_connect_complete(stcp_sock->active_sock, PJ_SUCCESS);
	} else if (status != PJ_EPENDING) {
		pj_perror(3, stcp_sock->pool->obj_name, status, "Failed to connect to %s",
			pj_sockaddr_print(dst_addr, addrtxt, sizeof(addrtxt), 3));
		PJ_LOG(3, (stcp_sock->pool->obj_name, "Failed to connect to %s",
			pj_sockaddr_print(dst_addr, addrtxt, sizeof(addrtxt), 3)));
		goto on_error;
	}
	return PJ_SUCCESS;

on_error:
	pj_stun_sock_destroy(stcp_sock);
	return status;
}

/*
* Create the STUN transport using the specified configuration.
*/
PJ_DEF(pj_status_t) pj_stun_sock_create( pj_stun_config *stun_cfg,
					 const char *name,
					 int af,
					 const pj_stun_sock_cb *cb,
					 const pj_stun_sock_cfg *cfg,
					 void *user_data,
					 pj_stun_sock **p_stun_sock)
{
    pj_pool_t *pool;
    pj_stun_sock *stun_sock;
    pj_stun_sock_cfg default_cfg;
    pj_sockaddr bound_addr;
    unsigned i;
    pj_uint16_t max_bind_retry;
    pj_status_t status;
	int opt = 1;

    PJ_ASSERT_RETURN(stun_cfg && cb && p_stun_sock, PJ_EINVAL);
    PJ_ASSERT_RETURN(af==pj_AF_INET()||af==pj_AF_INET6(), PJ_EAFNOTSUP);
    PJ_ASSERT_RETURN(!cfg || pj_stun_sock_cfg_is_valid(cfg), PJ_EINVAL);
    PJ_ASSERT_RETURN(cb->on_status, PJ_EINVAL);

    status = pj_stun_config_check_valid(stun_cfg);
    if (status != PJ_SUCCESS)
	return status;

    if (name == NULL)
	name = "stuntp%p";

    if (cfg == NULL) {
	pj_stun_sock_cfg_default(&default_cfg);
	cfg = &default_cfg;
    }


    /* Create structure */
    pool = pj_pool_create(stun_cfg->pf, name, 256, 512, NULL);
    stun_sock = PJ_POOL_ZALLOC_T(pool, pj_stun_sock);
    stun_sock->pool = pool;
    stun_sock->obj_name = pool->obj_name;
    stun_sock->user_data = user_data;
    stun_sock->af = af;
    stun_sock->sock_fd = PJ_INVALID_SOCKET;
    pj_memcpy(&stun_sock->stun_cfg, stun_cfg, sizeof(*stun_cfg));
    pj_memcpy(&stun_sock->cb, cb, sizeof(*cb));

    stun_sock->ka_interval = cfg->ka_interval;
    if (stun_sock->ka_interval == 0)
	stun_sock->ka_interval = PJ_STUN_KEEP_ALIVE_SEC;

    if (cfg->grp_lock) {
	stun_sock->grp_lock = cfg->grp_lock;
    } else {
	status = pj_grp_lock_create(pool, NULL, &stun_sock->grp_lock);
	if (status != PJ_SUCCESS) {
	    pj_pool_release(pool);
	    return status;
	}
    }

    pj_grp_lock_add_ref(stun_sock->grp_lock);
    pj_grp_lock_add_handler(stun_sock->grp_lock, pool, stun_sock,
			    &stun_sock_destructor);

    /* Create socket and bind socket */
    status = pj_sock_socket(af, pj_SOCK_DGRAM(), 0, &stun_sock->sock_fd);
    if (status != PJ_SUCCESS)
	goto on_error;

	status = pj_sock_setsockopt(stun_sock->sock_fd, pj_SOL_SOCKET(), pj_SO_REUSEADDR(), &opt, sizeof(opt));	
	if (status != PJ_SUCCESS) {
		PJ_LOG(4, (stun_sock->obj_name, "=====121212121 %d", status));
		goto on_error;
	}
		
    /* Apply QoS, if specified */
    status = pj_sock_apply_qos2(stun_sock->sock_fd, cfg->qos_type,
				&cfg->qos_params, 2, stun_sock->obj_name,
				NULL);
    if (status != PJ_SUCCESS && !cfg->qos_ignore_error)
	goto on_error;

    /* Apply socket buffer size */
    if (cfg->so_rcvbuf_size > 0) {
	unsigned sobuf_size = cfg->so_rcvbuf_size;
	status = pj_sock_setsockopt_sobuf(stun_sock->sock_fd, pj_SO_RCVBUF(),
					  PJ_TRUE, &sobuf_size);
	if (status != PJ_SUCCESS) {
	    pj_perror(3, stun_sock->obj_name, status,
		      "Failed setting SO_RCVBUF");
	} else {
	    if (sobuf_size < cfg->so_rcvbuf_size) {
		PJ_LOG(4, (stun_sock->obj_name, 
			   "Warning! Cannot set SO_RCVBUF as configured, "
			   "now=%d, configured=%d",
			   sobuf_size, cfg->so_rcvbuf_size));
	    } else {
		PJ_LOG(5, (stun_sock->obj_name, "SO_RCVBUF set to %d",
			   sobuf_size));
	    }
	}
    }
    if (cfg->so_sndbuf_size > 0) {
	unsigned sobuf_size = cfg->so_sndbuf_size;
	status = pj_sock_setsockopt_sobuf(stun_sock->sock_fd, pj_SO_SNDBUF(),
					  PJ_TRUE, &sobuf_size);
	if (status != PJ_SUCCESS) {
	    pj_perror(3, stun_sock->obj_name, status,
		      "Failed setting SO_SNDBUF");
	} else {
	    if (sobuf_size < cfg->so_sndbuf_size) {
		PJ_LOG(4, (stun_sock->obj_name, 
			   "Warning! Cannot set SO_SNDBUF as configured, "
			   "now=%d, configured=%d",
			   sobuf_size, cfg->so_sndbuf_size));
	    } else {
		PJ_LOG(5, (stun_sock->obj_name, "SO_SNDBUF set to %d",
			   sobuf_size));
	    }
	}
    }

    /* Bind socket */
    max_bind_retry = MAX_BIND_RETRY;
    if (cfg->port_range && cfg->port_range < max_bind_retry)
	max_bind_retry = cfg->port_range;
    pj_sockaddr_init(af, &bound_addr, NULL, 0);
    if (cfg->bound_addr.addr.sa_family == pj_AF_INET() || 
	cfg->bound_addr.addr.sa_family == pj_AF_INET6())
    {
	pj_sockaddr_cp(&bound_addr, &cfg->bound_addr);
    }
    status = pj_sock_bind_random(stun_sock->sock_fd, &bound_addr,
				 cfg->port_range, max_bind_retry);
    if (status != PJ_SUCCESS)
	goto on_error;

    /* Create more useful information string about this transport */
#if 0
    {
	pj_sockaddr bound_addr;
	int addr_len = sizeof(bound_addr);

	status = pj_sock_getsockname(stun_sock->sock_fd, &bound_addr, 
				     &addr_len);
	if (status != PJ_SUCCESS)
	    goto on_error;

	stun_sock->info = pj_pool_alloc(pool, PJ_INET6_ADDRSTRLEN+10);
	pj_sockaddr_print(&bound_addr, stun_sock->info, 
			  PJ_INET6_ADDRSTRLEN, 3);
    }
#endif

    /* Init active socket configuration */
    {
	pj_activesock_cfg activesock_cfg;
	pj_activesock_cb activesock_cb;

	pj_activesock_cfg_default(&activesock_cfg);
	activesock_cfg.grp_lock = stun_sock->grp_lock;
	activesock_cfg.async_cnt = cfg->async_cnt;
	activesock_cfg.concurrency = 0;

	/* Create the active socket */
	pj_bzero(&activesock_cb, sizeof(activesock_cb));
	activesock_cb.on_data_recvfrom = &on_data_recvfrom;
	activesock_cb.on_data_sent = &on_data_sent;
	status = pj_activesock_create(pool, stun_sock->sock_fd, 
				      pj_SOCK_DGRAM(), 
				      &activesock_cfg, stun_cfg->ioqueue,
				      &activesock_cb, stun_sock,
				      &stun_sock->active_sock);
	if (status != PJ_SUCCESS)
	    goto on_error;

	/* Start asynchronous read operations */
	status = pj_activesock_start_recvfrom(stun_sock->active_sock, pool,
					      cfg->max_pkt_size, 0);
	if (status != PJ_SUCCESS)
	    goto on_error;

	/* Init send keys */
	pj_ioqueue_op_key_init(&stun_sock->send_key, 
			       sizeof(stun_sock->send_key));
	pj_ioqueue_op_key_init(&stun_sock->int_send_key,
			       sizeof(stun_sock->int_send_key));
    }

    /* Create STUN session */
    {
	pj_stun_session_cb sess_cb;

	pj_bzero(&sess_cb, sizeof(sess_cb));
	sess_cb.on_request_complete = &sess_on_request_complete;
	sess_cb.on_send_msg = &sess_on_send_msg;
	status = pj_stun_session_create(&stun_sock->stun_cfg, 
					stun_sock->obj_name,
					&sess_cb, PJ_FALSE, 
					stun_sock->grp_lock,
					&stun_sock->stun_sess);
	if (status != PJ_SUCCESS)
	    goto on_error;
    }

    /* Associate us with the STUN session */
    pj_stun_session_set_user_data(stun_sock->stun_sess, stun_sock);

    /* Initialize random numbers to be used as STUN transaction ID for
     * outgoing Binding request. We use the 80bit number to distinguish
     * STUN messages we sent with STUN messages that the application sends.
     * The last 16bit value in the array is a counter.
     */
    for (i=0; i<PJ_ARRAY_SIZE(stun_sock->tsx_id); ++i) {
	stun_sock->tsx_id[i] = (pj_uint16_t) pj_rand();
    }
    stun_sock->tsx_id[5] = 0;


    /* Init timer entry */
    stun_sock->ka_timer.cb = &ka_timer_cb;
    stun_sock->ka_timer.user_data = stun_sock;

    /* Done */
    *p_stun_sock = stun_sock;
    return PJ_SUCCESS;

on_error:
    pj_stun_sock_destroy(stun_sock);
    return status;
}

/* Start socket. */
PJ_DEF(pj_status_t) pj_stun_sock_start( pj_stun_sock *stun_sock,
				        const pj_str_t *domain,
				        pj_uint16_t default_port,
				        pj_dns_resolver *resolver)
{
    pj_status_t status;

    PJ_ASSERT_RETURN(stun_sock && domain && default_port, PJ_EINVAL);

    pj_grp_lock_acquire(stun_sock->grp_lock);

    /* Check whether the domain contains IP address */
    stun_sock->srv_addr.addr.sa_family = (pj_uint16_t)stun_sock->af;
    status = pj_inet_pton(stun_sock->af, domain, 
			  pj_sockaddr_get_addr(&stun_sock->srv_addr));
    if (status != PJ_SUCCESS) {
	stun_sock->srv_addr.addr.sa_family = (pj_uint16_t)0;
    }

    /* If resolver is set, try to resolve with DNS SRV first. It
     * will fallback to DNS A/AAAA when no SRV record is found.
     */
    if (status != PJ_SUCCESS && resolver) {
	const pj_str_t res_name = pj_str("_stun._udp.");
	unsigned opt;

	pj_assert(stun_sock->q == NULL);

	/* Init DNS resolution option */
	if (stun_sock->af == pj_AF_INET6())
	    opt = (PJ_DNS_SRV_RESOLVE_AAAA_ONLY | PJ_DNS_SRV_FALLBACK_AAAA);
	else
	    opt = PJ_DNS_SRV_FALLBACK_A;

	status = pj_dns_srv_resolve(domain, &res_name, default_port, 
				    stun_sock->pool, resolver, opt,
				    stun_sock, &dns_srv_resolver_cb, 
				    &stun_sock->q);

	/* Processing will resume when the DNS SRV callback is called */

    } else {

	if (status != PJ_SUCCESS) {
	    pj_addrinfo ai;
	    unsigned cnt = 1;

	    status = pj_getaddrinfo(stun_sock->af, domain, &cnt, &ai);
	    if (cnt == 0)
		status = PJ_EAFNOTSUP;

	    if (status != PJ_SUCCESS) {
	        pj_grp_lock_release(stun_sock->grp_lock);
		return status;
	    }

	    pj_sockaddr_cp(&stun_sock->srv_addr, &ai.ai_addr);
	}

	pj_sockaddr_set_port(&stun_sock->srv_addr, (pj_uint16_t)default_port);

	/* Start sending Binding request */
	status = get_mapped_addr(stun_sock);
    }

    pj_grp_lock_release(stun_sock->grp_lock);
    return status;
}

/* Destructor */
static void stun_sock_destructor(void *obj)
{
    pj_stun_sock *stun_sock = (pj_stun_sock*)obj;

    if (stun_sock->q) {
	pj_dns_srv_cancel_query(stun_sock->q, PJ_FALSE);
	stun_sock->q = NULL;
    }

    /*
    if (stun_sock->stun_sess) {
	pj_stun_session_destroy(stun_sock->stun_sess);
	stun_sock->stun_sess = NULL;
    }
    */

    pj_pool_safe_release(&stun_sock->pool);

    TRACE_(("", "STUN sock %p destroyed", stun_sock));

}

/* Destroy */
PJ_DEF(pj_status_t) pj_stun_sock_destroy(pj_stun_sock *stun_sock)
{
    TRACE_((stun_sock->obj_name, "STUN sock %p request, ref_cnt=%d",
	    stun_sock, pj_grp_lock_get_ref(stun_sock->grp_lock)));

    pj_grp_lock_acquire(stun_sock->grp_lock);
    if (stun_sock->is_destroying) {
	/* Destroy already called */
	pj_grp_lock_release(stun_sock->grp_lock);
	return PJ_EINVALIDOP;
    }

    stun_sock->is_destroying = PJ_TRUE;
    pj_timer_heap_cancel_if_active(stun_sock->stun_cfg.timer_heap,
                                   &stun_sock->ka_timer, 0);

	// qing.zou added
	if (stun_sock->asock)
		pj_activesock_close(stun_sock->asock);

	if (stun_sock->active_sock != NULL) {
		stun_sock->sock_fd = PJ_INVALID_SOCKET;
		pj_activesock_close(stun_sock->active_sock);
	} else if (stun_sock->sock_fd != PJ_INVALID_SOCKET) {
		pj_sock_close(stun_sock->sock_fd);
		stun_sock->sock_fd = PJ_INVALID_SOCKET;
	}

    if (stun_sock->stun_sess) {
	pj_stun_session_destroy(stun_sock->stun_sess);
    }
    pj_grp_lock_dec_ref(stun_sock->grp_lock);
    pj_grp_lock_release(stun_sock->grp_lock);
    return PJ_SUCCESS;
}

/* Associate user data */
PJ_DEF(pj_status_t) pj_stun_sock_set_user_data( pj_stun_sock *stun_sock,
					        void *user_data)
{
    PJ_ASSERT_RETURN(stun_sock, PJ_EINVAL);
    stun_sock->user_data = user_data;
    return PJ_SUCCESS;
}


/* Get user data */
PJ_DEF(void*) pj_stun_sock_get_user_data(pj_stun_sock *stun_sock)
{
    PJ_ASSERT_RETURN(stun_sock, NULL);
    return stun_sock->user_data;
}

/* Get group lock */
PJ_DECL(pj_grp_lock_t *) pj_stun_sock_get_grp_lock(pj_stun_sock *stun_sock)
{
    PJ_ASSERT_RETURN(stun_sock, NULL);
    return stun_sock->grp_lock;
}

/* Notify application that session has failed */
static pj_bool_t sess_fail(pj_stun_sock *stun_sock, 
			   pj_stun_sock_op op,
			   pj_status_t status)
{
    pj_bool_t ret;

    PJ_PERROR(4,(stun_sock->obj_name, status, 
	         "Session failed because %s failed",
		 pj_stun_sock_op_name(op)));

    ret = (*stun_sock->cb.on_status)(stun_sock, op, status);

    return ret;
}

/* DNS resolver callback */
static void dns_srv_resolver_cb(void *user_data,
				pj_status_t status,
				const pj_dns_srv_record *rec)
{
    pj_stun_sock *stun_sock = (pj_stun_sock*) user_data;

    pj_grp_lock_acquire(stun_sock->grp_lock);

    /* Clear query */
    stun_sock->q = NULL;

    /* Handle error */
    if (status != PJ_SUCCESS) {
	sess_fail(stun_sock, PJ_STUN_SOCK_DNS_OP, status);
	pj_grp_lock_release(stun_sock->grp_lock);
	return;
    }

    pj_assert(rec->count);
    pj_assert(rec->entry[0].server.addr_count);
    pj_assert(rec->entry[0].server.addr[0].af == stun_sock->af);

    /* Set the address */
    pj_sockaddr_init(stun_sock->af, &stun_sock->srv_addr, NULL,
		     rec->entry[0].port);
    if (stun_sock->af == pj_AF_INET6()) {
	stun_sock->srv_addr.ipv6.sin6_addr = 
				    rec->entry[0].server.addr[0].ip.v6;
    } else {
	stun_sock->srv_addr.ipv4.sin_addr = 
				    rec->entry[0].server.addr[0].ip.v4;
    }

    /* Start sending Binding request */
    get_mapped_addr(stun_sock);

    pj_grp_lock_release(stun_sock->grp_lock);
}


/* Start sending STUN Binding request */
static pj_status_t get_mapped_addr(pj_stun_sock *stun_sock)
{
    pj_stun_tx_data *tdata;
    pj_status_t status;

    /* Increment request counter and create STUN Binding request */
    ++stun_sock->tsx_id[5];
    status = pj_stun_session_create_req(stun_sock->stun_sess,
					PJ_STUN_BINDING_REQUEST,
					PJ_STUN_MAGIC, 
					(const pj_uint8_t*)stun_sock->tsx_id, 
					&tdata);
    if (status != PJ_SUCCESS)
	goto on_error;
    
    /* Send request */
    status=pj_stun_session_send_msg(stun_sock->stun_sess, INTERNAL_MSG_TOKEN,
				    PJ_FALSE, PJ_TRUE, &stun_sock->srv_addr,
				    pj_sockaddr_get_len(&stun_sock->srv_addr),
				    tdata);
    if (status != PJ_SUCCESS && status != PJ_EPENDING)
	goto on_error;

    return PJ_SUCCESS;

on_error:
    sess_fail(stun_sock, PJ_STUN_SOCK_BINDING_OP, status);
    return status;
}

/* Get info */
PJ_DEF(pj_status_t) pj_stun_sock_get_info( pj_stun_sock *stun_sock,
					   pj_stun_sock_info *info)
{
    int addr_len;
    pj_status_t status;

    PJ_ASSERT_RETURN(stun_sock && info, PJ_EINVAL);

    pj_grp_lock_acquire(stun_sock->grp_lock);

    /* Copy STUN server address and mapped address */
    pj_memcpy(&info->srv_addr, &stun_sock->srv_addr,
	      sizeof(pj_sockaddr));
    pj_memcpy(&info->mapped_addr, &stun_sock->mapped_addr, 
	      sizeof(pj_sockaddr));

    /* Retrieve bound address */
    addr_len = sizeof(info->bound_addr);
    status = pj_sock_getsockname(stun_sock->sock_fd, &info->bound_addr,
				 &addr_len);
    if (status != PJ_SUCCESS) {
	pj_grp_lock_release(stun_sock->grp_lock);
	return status;
    }

    /* If socket is bound to a specific interface, then only put that
     * interface in the alias list. Otherwise query all the interfaces 
     * in the host.
     */
    if (pj_sockaddr_has_addr(&info->bound_addr)) {
	info->alias_cnt = 1;
	pj_sockaddr_cp(&info->aliases[0], &info->bound_addr);
    } else {
	pj_sockaddr def_addr;
	pj_uint16_t port = pj_sockaddr_get_port(&info->bound_addr); 
	unsigned i;

	/* Get the default address */
	status = pj_gethostip(stun_sock->af, &def_addr);
	if (status != PJ_SUCCESS) {
	    pj_grp_lock_release(stun_sock->grp_lock);
	    return status;
	}
	
	pj_sockaddr_set_port(&def_addr, port);
	
	/* Enum all IP interfaces in the host */
	info->alias_cnt = PJ_ARRAY_SIZE(info->aliases);
	status = pj_enum_ip_interface(stun_sock->af, &info->alias_cnt, 
				      info->aliases);
	if (status != PJ_SUCCESS) {
	    pj_grp_lock_release(stun_sock->grp_lock);
	    return status;
	}

	/* Set the port number for each address.
	 */
	for (i=0; i<info->alias_cnt; ++i) {
	    pj_sockaddr_set_port(&info->aliases[i], port);
	}

	/* Put the default IP in the first slot */
	for (i=0; i<info->alias_cnt; ++i) {
	    if (pj_sockaddr_cmp(&info->aliases[i], &def_addr)==0) {
		if (i!=0) {
		    pj_sockaddr_cp(&info->aliases[i], &info->aliases[0]);
		    pj_sockaddr_cp(&info->aliases[0], &def_addr);
		}
		break;
	    }
	}
    }

    pj_grp_lock_release(stun_sock->grp_lock);
    return PJ_SUCCESS;
}

/* Send application data */
PJ_DEF(pj_status_t) pj_stun_sock_send( pj_stun_sock *tcp_sock,
										pj_ioqueue_op_key_t *send_key,
										const void *pkt,
										unsigned pkt_len,
										unsigned flag)
{
	pj_ssize_t size;
	pj_status_t status;
	pj_activesock_t *asock = NULL;

	PJ_ASSERT_RETURN(tcp_sock && pkt, PJ_EINVAL);

	pj_grp_lock_acquire(tcp_sock->grp_lock);

	if (tcp_sock->is_server) {
		asock = tcp_sock->asock;
		if (send_key==NULL)
			send_key = &tcp_sock->op_key;
	} else {
		asock = tcp_sock->active_sock;
		if (send_key==NULL)
			send_key = &tcp_sock->send_key;
	}

	if (!asock) {
		/* We have been shutdown, but this callback may still get called
		* by retransmit timer.
		*/
		pj_grp_lock_release(tcp_sock->grp_lock);
		return PJ_EINVALIDOP;
	}

	unsigned total_len;
	//pj_uint8_t	tx_pkt[PJ_TURN_MAX_PKT_LEN];		//...
	pj_uint8_t*	tx_pkt = tcp_sock->tx_pkt;
	pj_stun_header_data *hd = (pj_stun_header_data *)tx_pkt;

	/* Calculate total length, including paddings */
	total_len = (pkt_len + sizeof(*hd) + 3) & (~3);
	if (total_len > sizeof(tcp_sock->tx_pkt)) {
		status = PJ_ETOOBIG;
		goto on_return;
	}

	//hd->number = pj_htons((pj_uint16_t)ch->num);
	hd->length = pj_htons((pj_uint16_t)pkt_len);
	pj_memcpy(hd+1, pkt, pkt_len);

	size = total_len;

	//printf("==================== tcp send\n");

	//status = pj_activesock_send(tcp_sock->active_sock, send_key, pkt, &size, 0);
	status = pj_activesock_send(asock, send_key, tx_pkt, &size, 0);

on_return:
	pj_grp_lock_release(tcp_sock->grp_lock);
	return status;
}

/* Send application data */
PJ_DEF(pj_status_t) pj_stun_sock_sendto( pj_stun_sock *stun_sock,
					 pj_ioqueue_op_key_t *send_key,
					 const void *pkt,
					 unsigned pkt_len,
					 unsigned flag,
					 const pj_sockaddr_t *dst_addr,
					 unsigned addr_len)
{
    pj_ssize_t size;
    pj_status_t status;

    PJ_ASSERT_RETURN(stun_sock && pkt && dst_addr && addr_len, PJ_EINVAL);
    
    pj_grp_lock_acquire(stun_sock->grp_lock);

    if (!stun_sock->active_sock) {
	/* We have been shutdown, but this callback may still get called
	 * by retransmit timer.
	 */
	pj_grp_lock_release(stun_sock->grp_lock);
	return PJ_EINVALIDOP;
    }

    if (send_key==NULL)
	send_key = &stun_sock->send_key;

    size = pkt_len;
    status = pj_activesock_sendto(stun_sock->active_sock, send_key,
                                  pkt, &size, flag, dst_addr, addr_len);

    pj_grp_lock_release(stun_sock->grp_lock);
    return status;
}

/* This callback is called by the STUN session to send packet */
static pj_status_t sess_on_send_msg(pj_stun_session *sess,
				    void *token,
				    const void *pkt,
				    pj_size_t pkt_size,
				    const pj_sockaddr_t *dst_addr,
				    unsigned addr_len)
{
    pj_stun_sock *stun_sock;
    pj_ssize_t size;

    stun_sock = (pj_stun_sock *) pj_stun_session_get_user_data(sess);
    if (!stun_sock || !stun_sock->active_sock) {
	/* We have been shutdown, but this callback may still get called
	 * by retransmit timer.
	 */
	return PJ_EINVALIDOP;
    }

    pj_assert(token==INTERNAL_MSG_TOKEN);
    PJ_UNUSED_ARG(token);

    size = pkt_size;
    return pj_activesock_sendto(stun_sock->active_sock,
				&stun_sock->int_send_key,
				pkt, &size, 0, dst_addr, addr_len);
}

/* This callback is called by the STUN session when outgoing transaction 
 * is complete
 */
static void sess_on_request_complete(pj_stun_session *sess,
				     pj_status_t status,
				     void *token,
				     pj_stun_tx_data *tdata,
				     const pj_stun_msg *response,
				     const pj_sockaddr_t *src_addr,
				     unsigned src_addr_len)
{
    pj_stun_sock *stun_sock;
    const pj_stun_sockaddr_attr *mapped_attr;
    pj_stun_sock_op op;
    pj_bool_t mapped_changed;
    pj_bool_t resched = PJ_TRUE;

    stun_sock = (pj_stun_sock *) pj_stun_session_get_user_data(sess);
    if (!stun_sock)
	return;

    PJ_UNUSED_ARG(tdata);
    PJ_UNUSED_ARG(token);
    PJ_UNUSED_ARG(src_addr);
    PJ_UNUSED_ARG(src_addr_len);

    /* Check if this is a keep-alive or the first Binding request */
    if (pj_sockaddr_has_addr(&stun_sock->mapped_addr))
	op = PJ_STUN_SOCK_KEEP_ALIVE_OP;
    else
	op = PJ_STUN_SOCK_BINDING_OP;

    /* Handle failure */
    if (status != PJ_SUCCESS) {
	resched = sess_fail(stun_sock, op, status);
	goto on_return;
    }

    /* Get XOR-MAPPED-ADDRESS, or MAPPED-ADDRESS when XOR-MAPPED-ADDRESS
     * doesn't exist.
     */
    mapped_attr = (const pj_stun_sockaddr_attr*)
		  pj_stun_msg_find_attr(response, PJ_STUN_ATTR_XOR_MAPPED_ADDR,
					0);
    if (mapped_attr==NULL) {
	mapped_attr = (const pj_stun_sockaddr_attr*)
		      pj_stun_msg_find_attr(response, PJ_STUN_ATTR_MAPPED_ADDR,
					0);
    }

    if (mapped_attr == NULL) {
	resched = sess_fail(stun_sock, op, PJNATH_ESTUNNOMAPPEDADDR);
	goto on_return;
    }

    /* Determine if mapped address has changed, and save the new mapped
     * address and call callback if so 
     */
    mapped_changed = !pj_sockaddr_has_addr(&stun_sock->mapped_addr) ||
		     pj_sockaddr_cmp(&stun_sock->mapped_addr, 
				     &mapped_attr->sockaddr) != 0;
    if (mapped_changed) {
	/* Print mapped adress */
	{
	    char addrinfo[PJ_INET6_ADDRSTRLEN+10];
	    PJ_LOG(4,(stun_sock->obj_name, 
		      "STUN mapped address found/changed: %s",
		      pj_sockaddr_print(&mapped_attr->sockaddr,
					addrinfo, sizeof(addrinfo), 3)));
	}

	pj_sockaddr_cp(&stun_sock->mapped_addr, &mapped_attr->sockaddr);

	if (op==PJ_STUN_SOCK_KEEP_ALIVE_OP)
	    op = PJ_STUN_SOCK_MAPPED_ADDR_CHANGE;
    }

    /* Notify user */
    resched = (*stun_sock->cb.on_status)(stun_sock, op, PJ_SUCCESS);

on_return:
    /* Start/restart keep-alive timer */
    if (resched)
	start_ka_timer(stun_sock);
}

/* Schedule keep-alive timer */
static void start_ka_timer(pj_stun_sock *stun_sock)
{
    pj_timer_heap_cancel_if_active(stun_sock->stun_cfg.timer_heap,
                                   &stun_sock->ka_timer, 0);

    pj_assert(stun_sock->ka_interval != 0);
    if (stun_sock->ka_interval > 0 && !stun_sock->is_destroying) {
	pj_time_val delay;

	delay.sec = stun_sock->ka_interval;
	delay.msec = 0;

	pj_timer_heap_schedule_w_grp_lock(stun_sock->stun_cfg.timer_heap,
	                                  &stun_sock->ka_timer,
	                                  &delay, PJ_TRUE,
	                                  stun_sock->grp_lock);
    }
}

/* Keep-alive timer callback */
static void ka_timer_cb(pj_timer_heap_t *th, pj_timer_entry *te)
{
    pj_stun_sock *stun_sock;

    stun_sock = (pj_stun_sock *) te->user_data;

    PJ_UNUSED_ARG(th);
    pj_grp_lock_acquire(stun_sock->grp_lock);

    /* Time to send STUN Binding request */
    if (get_mapped_addr(stun_sock) != PJ_SUCCESS) {
	pj_grp_lock_release(stun_sock->grp_lock);
	return;
    }

    /* Next keep-alive timer will be scheduled once the request
     * is complete.
     */
    pj_grp_lock_release(stun_sock->grp_lock);
}

/* Callback from active socket when incoming packet is received */
static pj_bool_t on_data_recvfrom(pj_activesock_t *asock,
				  void *data,
				  pj_size_t size,
				  const pj_sockaddr_t *src_addr,
				  int addr_len,
				  pj_status_t status)
{
    pj_stun_sock *stun_sock;
    pj_stun_msg_hdr *hdr;
    pj_uint16_t type;

    stun_sock = (pj_stun_sock*) pj_activesock_get_user_data(asock);
    if (!stun_sock)
	return PJ_FALSE;

    /* Log socket error */
    if (status != PJ_SUCCESS) {
	PJ_PERROR(2,(stun_sock->obj_name, status, "recvfrom() error"));
	return PJ_TRUE;
    }

    pj_grp_lock_acquire(stun_sock->grp_lock);

    /* Check that this is STUN message */
    status = pj_stun_msg_check((const pj_uint8_t*)data, size, 
    			       PJ_STUN_IS_DATAGRAM | PJ_STUN_CHECK_PACKET);
    if (status != PJ_SUCCESS) {
	/* Not STUN -- give it to application */
	goto process_app_data;
    }

    /* Treat packet as STUN header and copy the STUN message type.
     * We don't want to access the type directly from the header
     * since it may not be properly aligned.
     */
    hdr = (pj_stun_msg_hdr*) data;
    pj_memcpy(&type, &hdr->type, 2);
    type = pj_ntohs(type);

    /* If the packet is a STUN Binding response and part of the
     * transaction ID matches our internal ID, then this is
     * our internal STUN message (Binding request or keep alive).
     * Give it to our STUN session.
     */
    if (!PJ_STUN_IS_RESPONSE(type) ||
	PJ_STUN_GET_METHOD(type) != PJ_STUN_BINDING_METHOD ||
	pj_memcmp(hdr->tsx_id, stun_sock->tsx_id, 10) != 0) 
    {
	/* Not STUN Binding response, or STUN transaction ID mismatch.
	 * This is not our message too -- give it to application.
	 */
	goto process_app_data;
    }

    /* This is our STUN Binding response. Give it to the STUN session */
    status = pj_stun_session_on_rx_pkt(stun_sock->stun_sess, data, size,
				       PJ_STUN_IS_DATAGRAM, NULL, NULL,
				       src_addr, addr_len);

    status = pj_grp_lock_release(stun_sock->grp_lock);

    return status!=PJ_EGONE ? PJ_TRUE : PJ_FALSE;

process_app_data:
    if (stun_sock->cb.on_rx_data) {
	(*stun_sock->cb.on_rx_data)(stun_sock, data, (unsigned)size,
				    src_addr, addr_len);
	status = pj_grp_lock_release(stun_sock->grp_lock);
	return status!=PJ_EGONE ? PJ_TRUE : PJ_FALSE;
    }

    status = pj_grp_lock_release(stun_sock->grp_lock);
    return status!=PJ_EGONE ? PJ_TRUE : PJ_FALSE;
}

/* Callback from active socket about send status */
static pj_bool_t on_data_sent(pj_activesock_t *asock,
			      pj_ioqueue_op_key_t *send_key,
			      pj_ssize_t sent)
{
    pj_stun_sock *stun_sock;

    stun_sock = (pj_stun_sock*) pj_activesock_get_user_data(asock);
    if (!stun_sock)
	return PJ_FALSE;

    /* Don't report to callback if this is internal message */
    if (send_key == &stun_sock->int_send_key) {
	return PJ_TRUE;
    }

    /* Report to callback */
    if (stun_sock->cb.on_data_sent) {
	pj_bool_t ret;

	pj_grp_lock_acquire(stun_sock->grp_lock);

	/* If app gives NULL send_key in sendto() function, then give
	 * NULL in the callback too 
	 */
	if (send_key == &stun_sock->send_key)
	    send_key = NULL;

	/* Call callback */
	ret = (*stun_sock->cb.on_data_sent)(stun_sock, send_key, sent);

	pj_grp_lock_release(stun_sock->grp_lock);
	return ret;
    }

    return PJ_TRUE;
}

