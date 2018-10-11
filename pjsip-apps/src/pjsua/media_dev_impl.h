

#ifndef MEDIA_DEV_IMPL_H
#define MEDIA_DEV_IMPL_H

#include <pjsua-lib/pjsua.h>
#include "ice_client.h"

PJ_BEGIN_DECL

typedef struct tima_media_stream tima_media_stream;
typedef struct tima_media_dev_factory tima_media_dev_factory;

typedef int (*tima_put_packet)(void* user_data, char* msg, int msg_size);

/**
 * media device factory operations.
 */
typedef struct tima_media_dev_factory_op
{
	/**
     * Initialize the media device factory.
     *
     * @param f		The media device factory.
     */
    pj_status_t (*init)(tima_media_dev_factory *f);

	/**
     * Close this media device factory and release all resources back to the
     * operating system.
     *
     * @param f		The media device factory.
     */
    pj_status_t (*destroy)(tima_media_dev_factory *f);

	/**
     * Open the media device and create media stream.
     */
    pj_status_t (*create_stream)(tima_media_dev_factory *f,
								void *user_data, 
								pj_pool_t *pool,
								tima_put_packet put);

	//...start
} tima_media_dev_factory_op;

/**
 * This structure describes a media device factory. 
 */
struct tima_media_dev_factory
{
    tima_media_dev_factory_op *op;
};


typedef struct tima_media_stream_op
{
    pj_status_t (*start)(tima_media_stream *stream);

    pj_status_t (*stop)(tima_media_stream *stream);

    pj_status_t (*destroy)(tima_media_stream *stream);

} tima_media_stream_op;

struct tima_media_stream 
{
	tima_media_stream_op *op;
};


//...
pj_status_t file_create_stream(void *user_data, pj_pool_t *pool, 
							   tima_put_packet put,
							   tima_media_stream **mstream);
int file_stream_start(tima_media_stream *stream);
int file_destroy_stream(tima_media_stream* s);

PJ_END_DECL

#endif	/* MEDIA_DEV_IMPL_H */
