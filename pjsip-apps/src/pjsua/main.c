/* $Id: main.c 4752 2014-02-19 08:57:22Z ming $ */
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

#define THIS_FILE	"main.c"

//static pj_bool_t	    running = PJ_TRUE;
//static pj_status_t	    receive_end_sig;
//static pj_thread_t	    *sig_thread;
//static pjsua_app_cfg_t	    cfg;
//
///* Called when CLI (re)started */
//void on_app_started(pj_status_t status, const char *msg)
//{
//	pj_perror(3, THIS_FILE, status, (msg)?msg:"");
//}
//
//void on_app_stopped(pj_bool_t restart, int argc, char** argv)
//{
//	if (argv) {
//		cfg.argc = argc;
//		cfg.argv = argv;
//	}
//
//	running = restart;
//}

//#if defined(PJ_WIN32) && PJ_WIN32!=0
//#include <windows.h>
//
//static pj_thread_desc handler_desc;
//
//static BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
//{   
//    switch (fdwCtrlType) 
//    { 
//        // Handle the CTRL+C signal. 
// 
//        case CTRL_C_EVENT: 
//        case CTRL_CLOSE_EVENT: 
//        case CTRL_BREAK_EVENT: 
//        case CTRL_LOGOFF_EVENT: 
//        case CTRL_SHUTDOWN_EVENT: 
//	    pj_thread_register("ctrlhandler", handler_desc, &sig_thread);
//	    PJ_LOG(3,(THIS_FILE, "Ctrl-C detected, quitting.."));
//	    receive_end_sig = PJ_TRUE;
//            pjsua_app_destroy();	    
//	    ExitProcess(1);
//            PJ_UNREACHED(return TRUE;)
// 
//        default: 
// 
//            return FALSE; 
//    } 
//}
//
//static void setup_socket_signal()
//{
//}
//
//static void setup_signal_handler(void)
//{
//    SetConsoleCtrlHandler(&CtrlHandler, TRUE);
//}
//
//#else
#include <signal.h>
#include <getopt.h>


static void safe_flush(FILE *fp)
{
	int ch;
	while( (ch = fgetc(fp)) != EOF && ch != '\n' );
}

static void setup_socket_signal()
{
	signal(SIGPIPE, SIG_IGN);
}

static void setup_signal_handler(void) {}
//#endif


extern void file_entry(void);

// ./bin -c 1 -n
int main_func(int argc, char *argv[])
{
	int verbose = 0;
	int client = 0, external_network = 0;
	unsigned local_port = 0;
	unsigned remote_port = 0;
	char remote_ip[32] = {0};

	static char usage[] = "usage: [-n external_network] [-c client] \n";
	int opt;
	while ((opt = getopt (argc, argv, "h:nc:")) != -1)
	{
		switch (opt)
		{
		case 'h':
			printf("%s", usage);
			break;
		case 'c':
			client = atoi(optarg);
			break;
		case 'n':
			external_network = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case '?':
		default:
			printf("invalid option: %c\n", opt);
			printf("%s", usage);

			return -1;
		}
	}
#define SERVER_INTERNAL_NETWORK		"172.17.13.8"#define SERVER_EXTERNAL_NETWORK		"222.209.88.97"
	pj_status_t status = PJ_TRUE;
	
	char *server = NULL;
	if (external_network)
		server = SERVER_EXTERNAL_NETWORK;
	else
		server = SERVER_INTERNAL_NETWORK;

	//pj_bzero(&cfg, sizeof(cfg));
	//cfg.on_started = &on_app_started;
	//cfg.on_stopped = &on_app_stopped;
	//cfg.argc = argc;
	//cfg.argv = argv;

	setup_signal_handler();
	setup_socket_signal();

	char remote_uri[128] = {0};
	ice_info_t info = {0};
	if (client == 1) {
		strcpy(info.account, "101");
		strcpy(info.passwd, "101");
		strcpy(info.server, server);
		strcpy(info.realm, "172.17.13.8");

		strcpy(info.turn, server);
		strcpy(info.turn_port, "3488");
		strcpy(info.username, "username1");
		strcpy(info.password, "password1");
		sprintf(remote_uri, "sip:102@%s", info.server);
	} else {
		strcpy(info.account, "102");
		strcpy(info.passwd, "102");
		strcpy(info.server, server);
		strcpy(info.realm, "172.17.13.8");

		strcpy(info.turn, server);
		strcpy(info.turn_port, "3488");
		strcpy(info.username, "username2");
		strcpy(info.password, "password2");
		sprintf(remote_uri, "sip:101@%s", info.server);
	}

	ice_client_init(&info);


// 	pj_caching_pool		cache;	    /**< Global pool factory.		*/
// 	pj_pool_t			*pool;	
// 
// 	/* Init caching pool. */
// 	pj_caching_pool_init(&cache, NULL, 0);
// 
// 	/* Create memory pool for demo. */
// 	//pool = pjsua_pool_create("demo", 1000, 1000);
// 	/* Pool factory is thread safe, no need to lock */
// 	pool = pj_pool_create(&cache.factory, "demo", 1000, 1000, NULL);

	//file_entry(pool);
	file_entry();

	sleep(1);

	ice_client_status();

	char ch = '0';
	printf("\n\n\nplease press 'm' to start connect\n");
	while (ch != 'm') {
		scanf("%c", &ch);
	}
	printf("ch = %c\n\n\n", ch);

	ice_make_connect(remote_uri);

	while (1) {

		printf("\n\n\nEnter code: ");
		scanf("%c", &ch);
		safe_flush(stdin);
		printf("ch = %c\n\n", ch);

		switch (ch) {
			case 'm':
				ice_make_connect(remote_uri);
				break;
			case 'h':
				ice_client_disconnect();
				break;
			case '\n':
				ice_client_status();
				break;
			default:break;
		}

		//while (ch != '\n') {
		//	scanf("%c", &ch);
		//}
		//ch = '0';

		//ice_client_status();

		//sleep(3);

	}

	//pj_pool_release(pool);
	////pj_pool_safe_release(&pool);
	//pj_caching_pool_destroy(&cache);
	ice_client_destroy();

	return 0;
}

int main(int argc, char *argv[])
{
	return pj_run_app(&main_func, argc, argv, 0);
}
