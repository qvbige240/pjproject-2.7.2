
#include "media_dev_impl.h"


/* file stream */
struct file_stream
{
	tima_media_stream	base;

	pj_pool_t			*pool;
	void				*user_data;

	unsigned			buf_size;
	char				*buf;
	pj_thread_t			*file_thread;

	pj_sem_t			*sem;
	pj_mutex_t			*mutex;
	pj_bool_t			is_quitting;

	pj_bool_t			start;
	tima_put_packet		put_packet;
};

#define MAX_DATA_CHUNK_SIZE		1024
static int file_process_thread(void *args);
//extern int stream_transport_nonblock(void* handler);
//extern int stream_transport_send(void* handler, char* msg, int msg_size);

pj_status_t file_create_stream(void *user_data, pj_pool_t *pool, 
									  tima_put_packet put,
									  tima_media_stream **mstream)
{
	pj_status_t status;

	/* Create and Initialize stream descriptor */
	PJ_ASSERT_RETURN(pool != NULL, PJ_ENOMEM);

	struct file_stream* stream = PJ_POOL_ZALLOC_T(pool, struct file_stream);

	stream->pool = pool;
	stream->buf_size = MAX_DATA_CHUNK_SIZE;
	stream->user_data = user_data;
	stream->put_packet = put;
	status = pj_mutex_create_recursive(stream->pool, "file_stream", &stream->mutex);
	if (status != PJ_SUCCESS)
		return status;

	status = pj_sem_create(stream->pool, NULL, 0, 1, &stream->sem);
	if (status != PJ_SUCCESS)
		return status;

	/* Create file read thread. */
	status = pj_thread_create(stream->pool, "file_process_thread", file_process_thread, stream, 0, 0, &stream->file_thread);
	if (status != PJ_SUCCESS)
		return status;

	*mstream = stream;

	return PJ_SUCCESS;
}

int file_stream_start(tima_media_stream *stream)
{
	struct file_stream* s = stream;
	
	s->start = 1;

	return 0;
}

//static int file_destroy_stream(struct file_stream* stream)
int file_destroy_stream(tima_media_stream* s)
{
	struct file_stream *stream = (struct file_stream*)s;

	stream->is_quitting = 1;

	if (stream->file_thread) {
		//vpk_stream_t *pfs = (vpk_stream_t*)stream->user_data;
		//pj_sem_post(pfs->send->sem);
		//stream_transport_nonblock(stream->user_data);
		pj_sem_post(stream->sem);
		pj_thread_join(stream->file_thread);
		pj_thread_destroy(stream->file_thread);
		stream->file_thread = NULL;
	}

	if (stream->mutex) {
		pj_mutex_destroy(stream->mutex);
		stream->mutex = NULL;
	}

	if (stream->sem) {
		pj_sem_destroy(stream->sem);
		stream->sem = NULL;
	}

	return 0;
}

static int file_process_thread(void *args)
{
	struct file_stream *stream = (struct file_stream*)args;

	size_t offset = 0, size = MAX_DATA_CHUNK_SIZE;
	int file_size = 0;

	int result;
	FILE* fp = fopen("11.wav", "r");
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	stream->buf_size = (offset + size) <= file_size ? size : file_size;
	stream->buf = (char*) pj_pool_alloc(stream->pool, stream->buf_size);

	while (!stream->start) {
		pj_thread_sleep(500);
	}

	int cnt = 0;

	while(offset < file_size && !stream->is_quitting) {
		memset(stream->buf, 0x00, stream->buf_size);
		fseek(fp, offset, SEEK_SET);
		result = fread(stream->buf, 1, stream->buf_size, fp);
		if (result < 0) {
			printf("read file end!");
			break;
		}
		offset += result;

		//pj_mutex_lock(stream->mutex);
		//printf("[%d]read to send: %d ret=%d, %p\n", cnt++, stream->buf_size, result, stream->buf);
		printf("%05d ", cnt++);

		if (stream->put_packet)
			stream->put_packet(stream->user_data, stream->buf, result);

		//pj_mutex_unlock(stream->mutex);

		if (stream->is_quitting)
			break;


		//pj_thread_sleep(100);	// ms
	}

	printf("\n");

	if (fp) fclose(fp);

	return 0;
}

int vpk_file_save(const char* filename, void* data, size_t size)
{
	FILE* fp = 0;
	size_t ret = 0;
	//return_val_if_fail(filename != NULL && data != NULL, -1);

	fp = fopen(filename, "a+");
	if (fp != NULL && data)
	{
		ret = fwrite(data, 1, size, fp);
		fclose(fp);
	}
	if (ret != size)
		printf("fwrite size(%d != %d) incorrect!", ret, size);

	return ret;
}

