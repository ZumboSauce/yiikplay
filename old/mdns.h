#ifndef __MDNS__
#define __MDNS__

#ifdef _WIN32
    #include <WinSock2.h>
    #include <WS2tcpip.h>
    #include <Windows.h>
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
#endif

#include "mdns_types.h"
#include "util.h"

#define     MDNS_NETWORK_ADDRESS "224.0.0.251"
#define     MDNS_NETWORK_PORT 5353
#define     MDNS_MSG_BUF_LEN 1024
#define     MDNS_MSG_HEADER_LEN 12
#define     MDNS_QUERY_QINFO_SIZE 4
#define     MDNS_NAME_MAX_LEN 256
#define     DNS_COMPRESSION_FLAG 0b11
#define     MDNS_QUERY_QUERY_COUNT 4

#define     MDNS_DEFAULT_QUERY_COUNT 3

#define     DNS_RR_PTR  12
#define     DNS_RR_A    1
#define     DNS_RR_TXT  16
#define     DNS_RR_SRV  33

int             init_mdns_addr( int *fd );
int             _mdns_join( const int fd );
int             _mdns_exit( const int fd );
int             mdns_listen( const int fd, mdns_msg_raw_vec *raw_msgs, int buflen, double listen_time );
int             select_q( mdns_msg_vec *msgs, mdns_qtn_vec *qtns, char* srv );

#define _IS_QUERY(f) ( ~( f & (0b1 << 8) ) )
int             stom ( mdns_msg *mdns, char *raw );
void            _stomhead ( char **msg, mdns_head *head );
int             _stomqtn ( mdns_qtn *qtn, char **msg, char *msg_o );
int             _stomrr ( mdns_rr *rr, char **msg, char *msg_o );
int             dcmptostr ( u_char* msg, char* name, u_short idx );
int             _r_stoptr ( rr_ptr *ptr, char **msg, char *msg_o );
int             _r_stoa ( rr_a *a, char **msg, char *msg_o );
int             _r_stosrv ( rr_srv *srv, char **msg, char *msg_o );
int             _r_stotxt ( rr_txt *txt, char **msg, char *msg_o );
int mtos(mdns_msg *mdns, char *raw);
void _mtos_head(char *raw, mdns_msg *mdns);
#endif