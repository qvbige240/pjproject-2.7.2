/**
 * History:
 * ================================================================
 * 2018-09-26 qing.zou created
 *
 */
#ifndef LAN_DETECT_H
#define LAN_DETECT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif


#if defined(PJ_CONFIG_ANDROID)

#include <android/log.h>
#define LOG_TAG "p2p"
	#define LOG_D(...)   __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)

#else
	#define LOG_D   printf

#endif

int vpk_lan_server(int lport, int rport);
int vpk_lan_client(const char* ip, int port, int lport);

#ifdef __cplusplus
}
#endif

#endif //LAN_DETECT_H
