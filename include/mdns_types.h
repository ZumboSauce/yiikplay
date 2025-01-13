#define DNS_COMPRESSION_MASK 0xC0

#include <sys/types.h>

// splits s bits of b to h and 8 - s bits of b to l
#define WORDSPLIT( b, s, l, h ) {\
    h = b >> s ;\
    l = b & ~( 0b0 << 16 - s );\
}

#define MDNS_NAME_MAX_LEN 1024

typedef struct  r_srv
{
    char*       srv;
    u_short     len_srv;
    char*       proto;
    u_short     len_proto;
    char*       name;
    u_short     len_name;
    u_short     type;
    u_short     class;
    u_short     flush;
    u_int       ttl;
    u_short     datalen;
    u_short     prio;
    u_short     weight;
    u_short     port;
    char*       tgt;
    u_short     len_tgt;
}               r_srv;

typedef struct r_txt_f r_txt_f;
struct r_txt_f
{
    r_txt_f     *next;
    char        *f;
    u_short     len_f;
};

typedef struct  r_txt
{
    char*       name;
    short       len_name;
    u_short     type;
    u_short     class;
    u_short     flush;
    u_int       ttl;
    u_short     datalen;
    r_txt_f     *data;
}               r_txt;

typedef struct  r_ptr
{
    char*       name;
    short       len_name;
    u_short     type;
    u_short     class;
    u_short     flush;
    u_int       ttl;
    u_short     datalen;
    char*       dom;
    u_short     dom_len;
}               r_ptr;

typedef struct  r_a
{
    char*       name;
    short       len_name;
    u_short     type;
    u_short     class;
    u_short     flush;
    u_int       ttl;
    u_short     datalen;
    int         addr;
}               r_a;

typedef struct  r_tmp
{
    char        *name;
    u_short     len_name;
    u_short     type;
    u_short     class;
    u_short     flush;
    u_int       ttl;
    u_short     datalen;
}               r_tmp;

typedef struct  mdns_rr mdns_rr;
struct          mdns_rr
{
    mdns_rr     *next;
    u_char      type;
    union
    {
        r_a     *a;
        r_ptr   *ptr;
        r_txt   *txt;
        r_srv   *srv;
    };
};

typedef struct  q_ptr
{
    char*       name;
    short       len_name;
    u_short      type;
    u_short     class;
    char        cast;
}               q_ptr;

typedef enum    record_type
{
    A           = 1,
    PTR         = 12,
    TXT         = 16,
    SRV         = 33
}               record_type;

typedef struct mdns_qtn mdns_qtn;
struct          mdns_qtn
{
    mdns_qtn   *next;
    union
    {
        q_ptr   *ptr;
    };
    
};

typedef struct  mdns_msg_head
{
    u_short     tran_id;
    u_short     flags;
    u_short     qtn;
    u_short     rr;
    u_short     arr;
    u_short     auth_rr;
} mdns_msg_head;

typedef struct  mdns_msg
{
    mdns_msg_head   head;
    mdns_qtn        *qtn;
    u_short         c_qtn;
    mdns_rr         *rr;
    u_short         c_rr;
    mdns_rr         *a_rr;
    u_short         c_a_rr;   
}               mdns_msg;

void            addrtoi( char *a, u_int *i );
void            w_read( int c, char *in, u_short *out );
int             le_makeword( u_char *lb, u_char c  );
int             dns_cmp_res( char *raw, u_short idx, char *out );

int             r_txt_init( char *raw, u_short idx, r_txt *txt, r_tmp *tmp );
int             r_srv_init( char *raw, u_short idx, r_srv *srv, r_tmp *tmp );
int             r_ptr_init( char *raw, u_short idx, r_ptr *ptr, r_tmp *tmp );
int             r_a_init( char *raw, u_short idx, r_a *a, r_tmp *tmp );
int             q_ptr_init( char *raw, u_short idx, q_ptr *qtn );

int             mdns_rr_init( char *raw, u_short idx, mdns_rr *rr );
int             mdns_qtn_init( char *raw, u_short idx, mdns_qtn *qtn );
void            *mdns_msg_init( void *raw );