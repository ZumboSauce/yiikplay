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
#define     MDNS_SRV_MAX_LEN 256
#define     MDNS_POINTER 0b11
#define     MDNS_QUERY_QUERY_COUNT 4

#define     MDNS_DEFAULT_QUERY_COUNT 3

typedef struct rr_txt_dat
{
    char* k;
    char* v;
} rr_txt_dat;

typedef struct rr_txt
{
    char* name;
    short name_len;
    u_short class;
    char flush;
    u_int ttl;
    rr_txt_dat* data;
    u_short data_len;
} rr_txt;

typedef struct rr_srv
{
    char* srv;
    char* proto;
    char* name;
    u_short class;
    char flush;
    u_int ttl;
    u_short prio;
    u_short wgt;
    u_short port;
    char* tgt;
    u_short tgt_len;
} rr_srv;

typedef struct rr_a
{
    char* name;
    short name_len;
    u_short class;
    char flush;
    u_int ttl;
    int addr;
} rr_a;

typedef struct rr_data rr_data;

typedef struct mdns_add_rr
{
    u_short type;
    rr_data* data;
} mdns_add_rr;

typedef struct mdns_rr
{
    char* name;
    short name_len;
    u_short type;
    u_short class;
    char flush;
    u_int ttl;
    char* dom;
    u_short dom_len;
} mdns_rr;

typedef struct mdns_qtn
{
    char* name;
    short name_len;
    u_short type;
    u_short class;
    char cast;
} mdns_qtn;

typedef     struct {
    char *msg;
    u_short msglen;
    struct sockaddr_in *src;
    mdns_qtn *qtn;
    u_short qtn_cnt;
}   mdns_qry;

typedef     struct {
    mdns_qry **qry;
    u_short qry_cnt;
}   mdns_qry_vec;

typedef struct mdns_body
{
    mdns_qtn** qtns;
    mdns_rr** rrs;
} mdns_body;

typedef struct mdns_head
{
    u_short tran_id;
    u_short flags;
    u_short qtn;
    u_short rr;
    u_short auth_rr;
    u_short add_rr;
} mdns_head;


typedef struct mdns_msg
{
    mdns_head* head;
    mdns_body* body;
} mdns_msg;

int     init_mdns_addr();
int     _mdns_join(int fd);
int     _mdns_exit(int fd);
int     mdns_listen(int fd, mdns_msg ***msg, double listen_time);

#define _IS_QUERY(f) ( ~( f & (0b1 << 8) ) )
int     strtom(char* msg, mdns_msg* mdns);
int     _strtomhead(char *msg, mdns_head *head);
int     _mdns_name_res(u_char* msg, char* name, u_short idx);

#endif