

#include "vpk_list.h"
#include "ice_client.h"
#include "media_dev_impl.h"

static void on_connect_success(void *ctx, void *param);
static void on_socket_writable(void *ctx, void *param);
static void on_receive_message(void *ctx, void *pkt, pj_ssize_t bytes_read);


typedef struct pkt_node {
	list_t			node;

	int				is_compress;
	int				seq_num;
	int				buffer_size;
	char*			buffer;
} pkt_node_t;

typedef struct stream_transport
{
	list_t			head_entry;
	pj_sem_t		*sem;
	pj_mutex_t		*mutex;

	pj_bool_t		start;
	pj_bool_t		eagain;
	pj_bool_t		is_quitting;
	pj_thread_t		*stream_thread;

	int				seq_num;
	int				send_cnt;		/* count the send package in list for debug */
} stream_transport_t;

typedef struct vpk_stream
{
	iclient_callback		op;

	//pj_bool_t				start;

	tima_media_stream		*file;

	stream_transport_t		*send;

} vpk_stream_t;


static pkt_node_t* pkt_node_create(void *buf, int size, int seq)
{
	pkt_node_t* pkt = (pkt_node_t*)malloc(sizeof(pkt_node_t) + size);
	//return_val_if_fail(buf && length > 0, -1);

	if (pkt) 
	{
		INIT_LIST_HEAD(&pkt->node);

		pkt->is_compress	= 0;
		pkt->seq_num		= seq;
		pkt->buffer_size	= size;
		pkt->buffer			= (char*)pkt + sizeof(pkt_node_t);
		memcpy(pkt->buffer, buf, size);
	}

	return pkt;
}
static void pkt_node_release(pkt_node_t* node)
{
	if (node) {
		node->buffer = NULL;
		free(node);
	}
}

typedef int (*send_func)(const void *data, size_t size);

static int write_thread(void *args);

static int stream_transport_init(/*vpk_stream_t* stream, */pj_pool_t *pool, stream_transport_t **stream)
{
	pj_status_t status;
	stream_transport_t* thiz = PJ_POOL_ZALLOC_T (pool, stream_transport_t);

	//stream->send = thiz;
	INIT_LIST_HEAD(&thiz->head_entry);

	status = pj_mutex_create_recursive(pool, "stream_transport", &thiz->mutex);
	if (status != PJ_SUCCESS)
		return status;

	status = pj_sem_create(pool, NULL, 0, 1, &thiz->sem);
	if (status != PJ_SUCCESS)
		return status;

	/* Create stream send thread. */
	status = pj_thread_create(pool, "write_thread", write_thread, thiz, 0, 0, &thiz->stream_thread);
	if (status != PJ_SUCCESS)
		return status;

	*stream = thiz;

	return 0;
}

static int stream_transport_start(stream_transport_t *stream)
{
	if (stream)
		stream->start = 1;

	return 0;
}

static int stream_transport_status(stream_transport_t *stream, int eagain)
{
	if (stream)
		stream->eagain = eagain;

	return 0;
}

static int stream_write_process(void* handler, send_func process, void *data)
{
	int ret = 0;
	pkt_node_t* pkt_node = NULL;
	//vpk_stream_t *stream = (vpk_stream_t*)handler;
	//pjmedia_transport *tp = stream->transport;
	stream_transport_t* thiz = (stream_transport_t*)handler;
	//return_val_if_fail(thiz, -1);
	//if (!tp) {
	//	printf("========= tp is NULL =======\n");
	//	return 0;
	//}

	pj_mutex_lock(thiz->mutex);
	if (list_empty(&thiz->head_entry)) {
		pj_sem_post(thiz->sem);
		pj_mutex_unlock(thiz->mutex);
		return 0;
	}
	pkt_node = container_of(thiz->head_entry.next, pkt_node_t, node);
	list_del(thiz->head_entry.next);	//
	thiz->send_cnt--;
	//printf("=====send_cnt: %d\n", thiz->send_cnt);
	//printf("%d ", thiz->send_cnt);
	pj_mutex_unlock(thiz->mutex);
	if (pkt_node)
	{
		if (process)
			ret = process(pkt_node->buffer, pkt_node->buffer_size);	/* send active */
resendpkt:
		if (ret != 0) {
			PJ_LOG(4,("", "=====[%d]send_cnt: %d, status: %d\n", pkt_node->seq_num, thiz->send_cnt, ret));
			//sleep(2);
			stream_transport_status(thiz, 1);
			usleep(100000);
			//ret = process(pkt_node->buffer, pkt_node->buffer_size);	/* send active */
			//if (ret != 0)
			//	goto resendpkt;
		}

		//printf("=====send_cnt: %d, status: %d\n", thiz->send_cnt, ret);
		// ret is success ?
		// re-add node

		// release node
		pkt_node_release(pkt_node);
	}

	return ret;
}

static int write_thread(void *args)
{
	stream_transport_t *stream = (stream_transport_t*)args;

	//sleep(3);
	while(!stream->is_quitting) {
		pj_status_t status;

		if (stream->start && !stream->eagain)
			stream_write_process(stream, ice_packet_send, NULL);

		if (stream->is_quitting)
			break;

		pj_thread_sleep(1);
	}

	return 0;
}

int stream_transport_release(stream_transport_t* stream)
{
	pj_status_t status;
	stream_transport_t* thiz = stream;

	thiz->is_quitting = 1;

	if (thiz->stream_thread) {
		pj_thread_join(thiz->stream_thread);
		pj_thread_destroy(thiz->stream_thread);
		thiz->stream_thread = NULL;
	}

	if (thiz->mutex) {
		pj_mutex_destroy(thiz->mutex);
		thiz->mutex = NULL;
	}

	if (thiz->sem) {
		pj_sem_destroy(thiz->sem);
		thiz->sem = NULL;
	}

	// node release... pool release...

	return 0;
}

int stream_transport_send(void* handler, char* msg, int msg_size)
{
	pkt_node_t* send_pkg = NULL;
	vpk_stream_t* stream = (vpk_stream_t*)handler;
	stream_transport_t* thiz = stream->send;
	//return_val_if_fail(thiz && msg && msg_size > 0, -1);

	send_pkg = pkt_node_create(msg, msg_size, thiz->seq_num++);
	//return_val_if_fail(send_pkg, -1);

	pj_mutex_lock(thiz->mutex);
	list_add_tail(&send_pkg->node, &thiz->head_entry);
	thiz->send_cnt++;
	if (thiz->send_cnt > 5) {
		pj_mutex_unlock(thiz->mutex);
		pj_sem_wait(thiz->sem);
	} else
		pj_mutex_unlock(thiz->mutex);

	return 0;
}

int stream_transport_nonblock(void* handler)
{
	vpk_stream_t* stream = (vpk_stream_t*)handler;
	stream_transport_t* thiz = stream->send;

	pj_sem_post(thiz->sem);

	return 0;
}


vpk_stream_t* vpk_stream_create(pj_pool_t *pool)
{
	pj_status_t status;
	vpk_stream_t* thiz = PJ_POOL_ZALLOC_T (pool, vpk_stream_t);

	//iclient_callback op = {0};
	thiz->op.on_connect_success = on_connect_success;
	thiz->op.on_socket_writable = on_socket_writable;
	thiz->op.on_receive_message = on_receive_message;

	status = stream_transport_init(pool, &thiz->send);

	//stream->send = thiz;
// 	INIT_LIST_HEAD(&thiz->head_entry);
// 
// 	status = pj_mutex_create_recursive(pool, "file_transport", &thiz->mutex);
// 	if (status != PJ_SUCCESS)
// 		return status;
// 
// 	status = pj_sem_create(pool, NULL, 0, 1, &thiz->sem);
// 	if (status != PJ_SUCCESS)
// 		return status;
// 
// 	/* Create stream send thread. */
// 	status = pj_thread_create(pool, "write_thread", write_thread, thiz, 0, 0, &thiz->stream_thread);
// 	if (status != PJ_SUCCESS)
// 		return status;
// 
// 	*stream = thiz;

	return thiz;
}

void vpk_stream_destroy(vpk_stream_t *stream)
{
	if (stream)
	{
		if (stream->send)
			stream_transport_release(stream->send);
	}
}

void file_demo_destroy(vpk_stream_t *stream)
{
	if (stream)
	{
		if (stream->file)
			file_destroy_stream(stream->file);

		if (stream->send)
			stream_transport_release(stream->send);
	}
}


void file_entry(void)
{
	pj_caching_pool		cache;	    /**< Global pool factory.		*/
	pj_pool_t			*pool;	

	/* Init caching pool. */
	pj_caching_pool_init(&cache, NULL, 0);

	/* Create memory pool for demo. */
	//pool = pjsua_pool_create("demo", 1000, 1000);
	/* Pool factory is thread safe, no need to lock */
	pool = pj_pool_create(&cache.factory, "demo", 1000, 1000, NULL);


	vpk_stream_t* stream = vpk_stream_create(pool);

	//tima_media_stream *file_stream = stream->file;
	file_create_stream(stream, pool, stream_transport_send, &stream->file);

	//file_stream_start(file_stream);

	ice_client_register(&stream->op);
	//ice_make_connect(&stream->op, uri);
}


static void on_connect_success(void *ctx, void *param)
{
	vpk_stream_t *thiz = (vpk_stream_t *)ctx;

	pj_assert(ctx);

	file_stream_start(thiz->file);
	stream_transport_start(thiz->send);
}

static void on_socket_writable(void *ctx, void *param)
{
	vpk_stream_t *thiz = (vpk_stream_t *)ctx;

	pj_assert(ctx);

	/* start send */
	stream_transport_status(thiz->send, 0);
}

#include <time.h>

static struct timeval prev;	

static int total_read = 0;
static int index_read = 0;
extern int vpk_file_save(const char* filename, void* data, size_t size);

static int time_sub(struct timeval *result, struct timeval *prev, struct timeval *next)
{
	if (prev->tv_sec > next->tv_sec) return -1;
	if (prev->tv_sec == next->tv_sec && prev->tv_usec > next->tv_usec) return -1;

	result->tv_sec = next->tv_sec - prev->tv_sec;
	result->tv_usec = next->tv_usec - prev->tv_usec;
	if (result->tv_usec < 0)
	{
		result->tv_sec--;
		result->tv_usec += 1000000;
	}

	return 0;
}
static void on_receive_message(void *ctx, void *pkt, pj_ssize_t bytes_read)
{
	int stotal, unit;
	double rate;
	double elapsed;
	struct timeval result, next;	

	if (index_read == 0)
		gettimeofday(&prev, 0);

	gettimeofday(&next, 0);
	//vpk_timersub(&next, &prev, &result);
	time_sub(&result, &prev, &next);
	elapsed = result.tv_sec + (result.tv_usec / 1.0e6);
	//LOG_D("vpk time elapsed: %.6f, %d(s) %d(us) \n", elapsed, result.tv_sec, result.tv_usec);

	//printf("pkt[%d] %d + %d = %d \n", index_read, total_read, bytes_read, total_read+bytes_read);
	//index_read++;
	total_read += bytes_read;
	rate = total_read * 1.0 / (result.tv_sec * 1000 + result.tv_usec / 1.0e3 + 1);

	//stotal = total_read;
	//if (stotal / 10000 > 1) {
	//	unit++;
	//	stotal = stotal / 1000;
	//	if (stotal / 10000 > 1) {
	//		unit++;
	//		stotal = stotal / 1000;
	//	}
	//}
	PJ_LOG(4,("", "pkt[%d] %d + %d = %d   %.1fKB/s  %.1fs", index_read++, total_read-bytes_read, bytes_read, total_read, rate, elapsed));
	//printf("pkt[%d] %d + %d = %d   %.1fKB/s  %.1f\n", index_read++, total_read, bytes_read, total_read, rate, elapsed);
	vpk_file_save("./recv.txt", pkt, bytes_read);
}
