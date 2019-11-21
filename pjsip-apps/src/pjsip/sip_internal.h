/**
 * History:
 * ================================================================
 * 2019-11-20 qing.zou created
 *
 */

#ifndef SIP_INTERNAL_H
#define SIP_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif


#define MAX_CALLS	8
#define TRACE_(x)   PJ_LOG(3,x)

typedef struct sip_call_t
{
    pjsip_inv_session	*inv;
} sip_call_t;

struct sip_data
{
    pj_caching_pool     cp;         /** Global pool factory.    **/
    pj_pool_t		   *pool;

    pjsip_endpoint	   *endpt;	    /** Global endpoint.        **/
    pjsip_module	    mod;	    /** sip's PJSIP module.   **/

    sip_call_t          call[MAX_CALLS];

    pj_bool_t           quit;
    pj_thread_t        *worker_thread;

    pj_bool_t           enable_msg_logging;

    user_info_t         info;
};

void sip_perror(const char *sender, const char *title, pj_status_t status);
int sip_register(struct sip_data *app);


#ifdef __cplusplus
}
#endif

#endif // SIP_INTERNAL_H
