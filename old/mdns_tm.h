#ifndef __MDNS_TYPES_
#define __MDNS_TYPES__


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

typedef union mdns_rr
{
    rr_ptr ptr;
    rr_a a;
    rr_srv srv;
    rr_txt txt;
} mdns_rr;

typedef struct mdns_qtn
{
    u_char type;
    char* name;
    short name_len;
    u_short class;
    char cast;
} mdns_qtn;

typedef struct mdns_qtn_vec
{
    mdns_qtn **qtns;
    u_short qtn_ct;
} mdns_qtn_vec;

typedef struct mdns_body
{
    mdns_qtn* qtns;
    mdns_rr* rrs;
    mdns_rr* arrs;
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

typedef struct mdns_msg_raw_vec
{
    struct mdns_msg_raw **msgs_raw;
    u_short raw_ct;
} mdns_msg_raw_vec;

typedef struct mdns_msg
{
    struct sockaddr_in *info;
    mdns_head head;
    mdns_body body;
} mdns_msg;

typedef struct mdns_msg_vec
{
    mdns_msg **msgs;
    u_short msg_ct;
} mdns_msg_vec;

typedef struct label label;
struct label
{
    char *l;
    u_short l_len;
    u_short idx;
    label *next;
};

typedef struct label_t
{
    label *f;
    label *last;
} label_t;

typedef struct dns_rr_base dns_rr_base;

typedef struct dns_q_base dns_q_base;
struct dns_q_base
{
    dns_q_base *next;
    u_char type;   
};

typedef struct dns_q_ptr
{

    u_char type;
    char* name;
    short name_len;
    u_short class;
    char cast;
} dns_q_ptr;

typedef union mdns_qtn
{
    dns_q_ptr ptr;
} mdns_qtn;

typedef struct mdns_msg_tmp
{
    struct sockaddr_in *info;
    mdns_head head;
    mdns_qtn *qtn;
    
}

#endif