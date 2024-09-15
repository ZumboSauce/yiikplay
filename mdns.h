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

typedef struct rr_txt_dat rr_txt_dat;
struct rr_txt_dat
{
    char *k;
    u_short k_len;
    rr_txt_dat *next;
};

typedef struct rr_txt
{
    u_char type;
    char* name;
    short name_len;
    u_short class;
    char flush;
    u_int ttl;
    rr_txt_dat *data;
    u_short data_len;
} rr_txt;

typedef struct rr_srv
{
    u_char type;
    char* name;
    short name_len;
    u_short class;
    char flush;
    u_int ttl;
    char* srv;
    char* proto;
    char* n;
    u_short prio;
    u_short wgt;
    u_short port;
    char* tgt;
    u_short tgt_len;
} rr_srv;

typedef struct rr_a
{
    u_char type;
    char* name;
    short name_len;
    u_short class;
    char flush;
    u_int ttl;
    int addr;
} rr_a;

typedef struct rr_ptr
{
    u_char type;
    char* name;
    short name_len;
    u_short class;
    char flush;
    u_int ttl;
    char* dom;
    u_short dom_len;
} rr_ptr;

typedef struct rr_base
{
    u_char type;
    char* name;
    short name_len;
    u_short class;
    char flush;
    u_int ttl;
} rr_base;

typedef struct mdns_rr
{
    union
    {
        rr_ptr ptr;
        rr_a a;
        rr_srv srv;
        rr_txt txt;
    } *rr;
} mdns_rr;

typedef struct mdns_qtn
{
    u_char type;
    char* name;
    short name_len;
    u_short class;
    char cast;
} mdns_qtn;

typedef struct mdns_body
{
    mdns_qtn** qtns;
    mdns_rr** rrs;
    mdns_rr** arrs;
} mdns_body;

typedef struct mdns_head
{
    u_short tran_id;
    u_short flags;
    u_short qtn;
    u_short rr;
    u_short auth_rr;
    u_short arr;
} mdns_head;

typedef struct mdns_msg_raw
{
    struct sockaddr_in *info;
    char* msg;
    u_short msg_len;
} mdns_msg_raw;

typedef struct mdns_msg_raw_ct
{
    mdns_msg_raw **msg_raw;
} mdns_msg_raw_ct;

typedef struct mdns_msg
{
    struct sockaddr_in *info;
    mdns_head* head;
    mdns_body* body;
} mdns_msg;

int             init_mdns_addr( int *fd );
int             _mdns_join( const int fd );
int             _mdns_exit( const int fd );
int             mdns_listen( const int fd, mdns_msg_raw_ct *msg_raw_ct, int buflen, double listen_time );

#define _IS_QUERY(f) ( ~( f & (0b1 << 8) ) )
int             strtom( mdns_msg *mdns, mdns_msg_raw *msg_raw );
void            _strtomhead( char *msg, mdns_head *head );
int             _strtomqtn( mdns_qtn **qtns, u_short qtn_ct, char **msg );
int             _strtomrr( mdns_rr **rrs, u_short rr_ct, char **msg );
int             _mdns_name_res( u_char* msg, char* name );
int             _dns_r_ptr( rr_ptr *ptr, char **msg );
int             _dns_r_a( rr_a *a, char **msg );
int             _dns_r_srv( rr_srv *srv, char **msg );
int             _dns_r_txt( rr_txt *txt, char **msg );
int             _mdns_qtn_res( mdns_qtn *qtn, char **msg );
int             _mdns_rr_res( mdns_rr *rr, char **msg );
#endif