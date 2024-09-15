#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifdef _WIN32
    #include <WinSock2.h>
    #include <WS2tcpip.h>
    #include <Windows.h>
    #include <signal.h>
    
    void    _sig_handler(){
        WSACleanup();
    }
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <poll.h>
    #include <unistd.h>
#endif

#include "mdns.h"
#include "airplay_mdns.h"
#include "util.h"

//initializes network ressources
int             init_mdns_addr( int *fd )
{
    //start winsock dll
    #ifdef _WIN32
        WSADATA wsa_data;
        if (WSAStartup(MAKEWORD(2,2), &wsa_data)) {
            perror("WSAStartup");
            return -1;
        }
        signal(SIGINT, _sig_handler);
        signal(SIGILL, _sig_handler);
        signal(SIGSEGV, _sig_handler);
        signal(SIGABRT, _sig_handler);
        signal(SIGSEGV, _sig_handler);
    #endif

    //create udp socket
    *fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (*fd < 0) {
        perror("socket");
        return -1;
    }
    
    //enable reusing ports
    u_int enable_reuseaddr = 1;
    if ( setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR, (char*) &enable_reuseaddr, sizeof(enable_reuseaddr)) < 0) {
        perror("reuse addr failed");
        return -1;
    }

    //bind address
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(MDNS_NETWORK_PORT);
    if ( bind(*fd, (struct sockaddr*) &addr, sizeof(addr)) < 0 ) {
        perror("bind");
        return -1;
    }
    return 1;
}

//join mdns network
int             _mdns_join(int fd)
{
    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(struct ip_mreq));
    inet_pton(AF_INET, MDNS_NETWORK_ADDRESS, &mreq.imr_multiaddr.s_addr);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if ( setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*) &mreq, sizeof(mreq)) < 0 ) {
        perror("setsockopt");
        return -1;
    }
    return 1;
}

//leave mdns network
int             _mdns_exit(int fd)
{
    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(struct ip_mreq));
    inet_pton(AF_INET, MDNS_NETWORK_ADDRESS, &mreq.imr_multiaddr.s_addr);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if ( setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char*) &mreq, sizeof(mreq)) < 0 ) {
        perror("setsockopt");
        return -1;
    }
    return 1;
}

//extracts string from mdns message dealing ith dns compression
int             _mdns_name_res( u_char* msg, char* name )
{
    if( *msg == 0 )
    {
        name[0] = '\0';
        return 1;
    }
    else if ( ( *msg >> 6 ) == DNS_COMPRESSION_FLAG )
    {
        char *msg_compression = msg + MAKEWORD( *( msg + 1 ), *msg & ( ~( DNS_COMPRESSION_FLAG << 6 ) ) );
        _mdns_name_res( msg_compression, name );
        return 2;
    }
    else
    {
        strncpy( name, msg + 1, *msg );
        return *msg + _mdns_name_res( msg, name + *msg + 1 );
    }
}

//converts string ptr rr to struct
inline int      _dns_r_ptr( rr_ptr *ptr, char **msg )
{
    u_short data_len = MAKEWORD( *msg[9], *msg[8] );
    char dom[256];
    _mdns_name_res(*msg + 10, dom);
    ptr->dom_len    = strlen(dom);
    ptr->dom        = ( char * ) malloc( ptr->dom_len * sizeof(char) );
    if( ptr->dom == NULL )
    {
        perror("malloc");
        return -1;
    }
    strcpy( ptr->dom, dom );
    *msg += 10 + data_len;
    return 1;
}

//converts string a rr to struct
inline int      _dns_r_a( rr_a *a, char **msg )
{
    u_short data_len = MAKEWORD( *msg[9], *msg[8] );
    a->addr         = MAKEDWORD( *msg[10], *msg[11], *msg[12], *msg[13] );
    *msg += 14 * sizeof(u_char);
    return 1;
}

//converts string srv rr to struct
inline int      _dns_r_srv( rr_srv *srv, char **msg )
{
    char **labels = ( char ** ) malloc( 3 * sizeof( char * ) );

    char *name = srv->name;
    for( int i = 0; i < 3; i++ )
    {
        char *sub = strchr( name + 1, '_' );
        if( sub == NULL )
        {
            labels[i] = ( char * ) malloc( strlen(name) * sizeof( char ) );
            strcpy( labels[i], name );
        }
        u_short label_len = sub - name;
        labels[i] = ( char * ) malloc( label_len * sizeof( char ) );
        strncpy( labels[i], name, label_len - 1 );
        labels[i][label_len] = '\0';
        name += label_len;
    }

    srv->srv            = labels[0];
    srv->proto          = labels[1];
    srv->n              = labels[2];
    u_short data_len    = MAKEWORD( *msg[9], *msg[8] );
    srv->prio           = MAKEWORD( *msg[11], *msg[10] );
    srv->wgt            = MAKEWORD( *msg[13], *msg[12] );
    srv->port           = MAKEWORD( *msg[15], *msg[14] );
    char tgt[256];
    srv->tgt_len        = _mdns_name_res( *msg + 16, tgt );
    srv->tgt            = ( char * ) malloc( srv->tgt_len * sizeof(char) );
    strcpy( srv->tgt, tgt );
    *msg += 16 + srv->tgt_len;
    return 1;
}

//converts string txt rr to struct
inline int      _dns_r_txt( rr_txt *txt, char **msg )
{
    u_short data_len    = MAKEWORD( *msg[9], *msg[8] );
    
    char *idx = 10 + *msg;
    *msg += 10 + data_len;
    txt->data  = ( rr_txt_dat * ) malloc( sizeof( rr_txt_dat ) );
    if( txt->data == NULL )
    {
        perror("malloc");
        return -1;
    }

    rr_txt_dat *cur = txt->data;
    while ( idx < *msg )
    {
        cur->k_len = *idx;
        cur->k = ( char * ) malloc( *idx * sizeof(char) );
        strncpy( cur->k, idx + 1, *idx );
        idx += *idx + 1;
        cur->next  = ( rr_txt_dat * ) malloc( sizeof( rr_txt_dat ) );
        if( cur->next == NULL )
        {
            perror("malloc");
            return -1;
        }
        cur = cur->next;
    }

    return 1;
}

//preps string mdns rr/arr for conversion to struct 
int             _mdns_rr_prep( rr_base *base, char* name, u_char type, char **msg )
{
    base->name_len      = strlen( name );
    base->name          = ( char * ) malloc( base->name_len * sizeof(char) );
    if( base->name == NULL )
    {
        perror("malloc");
        return -1;
    }
    strcpy( base->name, name );
    base->type          = type;
    u_short cqu         = MAKEWORD( *msg[3], *msg[2] );
    base->class         = cqu & ( ~ (1 << 15) );
    base->flush         = cqu >> 15;
    base->ttl           = MAKEDWORD( *msg[7], *msg[6], *msg[5], *msg[4] );
}

//detects type of and preps string mdns rr/arr for conversion to struct
int             _mdns_rr_res( mdns_rr *rr, char **msg )
{
    char name[MDNS_NAME_MAX_LEN];
    *msg += _mdns_name_res( *msg, name ) + 1;
    u_short type = MAKEWORD( *(*msg + 1), **msg );

    _mdns_rr_prep( ( rr_base * ) rr->rr, name, type, msg );

    switch ( type )
    {
        case DNS_RR_PTR:
            return _dns_r_ptr( &(rr->rr->ptr), msg );
            break;
        case DNS_RR_A:
            return _dns_r_a( &(rr->rr->a), msg );
            break;
        case DNS_RR_SRV:
            return _dns_r_srv( &(rr->rr->srv), msg );
            break;
        case DNS_RR_TXT:
            return _dns_r_txt( &(rr->rr->txt), msg );
            break;
        default:
            fprintf(stderr, "Error: DNS record of type %d not supported\n", type);
            return -1;
    }
}

//detects type of and preps string mdns qtn for conversion to struct
int             _mdns_qtn_res( mdns_qtn *qtn, char **msg )
{
    char name[MDNS_NAME_MAX_LEN];
    *msg += _mdns_name_res( *msg, name ) + 1;
    u_char type = MAKEWORD( *(*msg + 1), **msg );

    qtn->name_len   = strlen( name );
    qtn->name       = ( char * ) malloc( qtn->name_len * sizeof(char) );
    if( qtn->name == NULL )
    {
        perror("malloc");
        return -1;
    }
    strcpy( qtn->name, name );

    qtn->type       = type;
    u_short cqu     = MAKEWORD( *msg[3], *msg[2]);
    qtn->class      = cqu & ( ~ (1 << 15) );
    qtn->cast       = cqu >> 15 ;
    *msg += 4;
}

//converts string mdns qtn to struct
int             _strtomrr( mdns_rr **rrs, u_short rr_ct, char **msg )
{
    rrs = ( mdns_rr ** ) malloc( rr_ct * sizeof( mdns_rr * ) );
    for( int i = 0; i < rr_ct; i++ )
    {
        mdns_rr *rr = rrs[i];
        rr = ( mdns_rr * ) malloc( sizeof( mdns_rr ) );

        if ( rr == NULL )
        {
            perror("malloc");
            return -1;
        }

        if( _mdns_rr_res( rr, msg ) < 1 )
        {
            return -1;
        }
    }
}

//converts string mdns qtn to struct
int             _strtomqtn( mdns_qtn **qtns, u_short qtn_ct, char **msg )
{
    qtns = (mdns_qtn **) malloc( qtn_ct * sizeof(mdns_qtn *) );
    for( int i = 0; i < qtn_ct; i++ )
    {
        mdns_qtn *qtn = qtns[i]; 
        qtn = ( mdns_qtn * ) malloc( sizeof( mdns_qtn ) );

        if ( qtn == NULL)
        {
            perror("malloc");
            return -1;
        }

        if( _mdns_qtn_res( qtn, msg ) < 1)
        {
            return -1;
        }
    }
}

//extracts header from string mdns message
inline void     _strtomhead(char *msg, mdns_head *head)
{
    head->tran_id   = MAKEWORD(msg[1], msg[0]);
    head->flags     = MAKEWORD(msg[3], msg[2]);
    head->qtn       = MAKEWORD(msg[5], msg[4]);
    head->rr        = MAKEWORD(msg[7], msg[6]);
    head->auth_rr   = MAKEWORD(msg[9], msg[8]);
    head->arr    = MAKEWORD(msg[11], msg[10]);
}

//converts string mdns message to struct
int             strtom( mdns_msg *mdns, mdns_msg_raw *msg_raw )
{
    _strtomhead(msg_raw->msg, mdns->head);

    mdns->body->rrs = NULL;
    mdns->body->arrs = NULL;

    char* msg = msg_raw->msg + MDNS_MSG_HEADER_LEN; 
    
    if ( _strtomqtn( mdns->body->qtns, mdns->head->qtn, &msg ) < 1 )
    {
        printf("Error: MDNS question processing\n");
        return -1;
    }

    if ( _strtomrr( mdns->body->rrs, mdns->head->rr, &msg ) < 1 )
    {
        printf("Error: MDNS ressource record processing\n");
        return -1;
    }

    if ( _strtomrr( mdns->body->arrs, mdns->head->arr, &msg ) < 1 )
    {
        printf("Error: MDNS additional ressource record processing\n");
        return -1;
    }
}

//filters mdns messages
int             mdns_select(mdns_msg **msg, mdns_msg_raw **msg_raw, int msg_raw_ct, char* srv, char srv_len, char dis)
{
    for ( int i = 0; i < msg_raw_ct; i++ )
    {
        strtom( msg[i], msg_raw[i] );
    }
}

//listens to mdns network and stores all messages
int             mdns_listen(int fd, mdns_msg_raw_ct *raw_ct, int buflen, double listen_time)
{

    if ( _mdns_join(fd) < -1 )
    {
        return -1;
    }

    mdns_msg_raw **msg;

    u_short msg_ct = 0, msg_alloc = 2;
    time_t start, cur;
    start = cur = time(NULL);

    while ( difftime(cur, start) < (double)listen_time )
    {
        printf("%d", difftime(cur, start));
        cur = time(NULL);

        struct pollfd mdns_poll = 
        {
            .fd = fd,
            .events = POLLRDNORM
        };

        //poll mdns socket
        #ifdef _WIN32
        int t = WSAPoll(&mdns_poll, 1, MAX( ((start + listen_time) - cur) * 1000, 0 ));
        if (t == SOCKET_ERROR)
        {
            printf("poll: %d\n", WSAGetLastError());
            return -1;
        }
        #else
        int t = poll(&mdns_poll, 1, MAX( ((start + listen_time) - cur) * 1000, 0));
        if (t == -1)
        {
            perror("poll");
            return -1;
        }
        #endif

        if (t && mdns_poll.revents != 0)
        {
            if (mdns_poll.revents & POLLRDNORM)
            {   
                u_char* msgbuf = (u_char*) malloc(MDNS_MSG_BUF_LEN);
                if (msgbuf == NULL)
                {
                    perror("malloc");
                    return -1;
                }

                struct sockaddr_in *src = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
                if (src == NULL)
                {
                    perror("malloc");
                    return -1;
                }
                memset(src, 0, sizeof(struct sockaddr_in));
                int srclen = sizeof(struct sockaddr_in);
                
                int nbytes = recvfrom(fd, msgbuf, MDNS_MSG_BUF_LEN, 0, (struct sockaddr *) src, &srclen);
                if (nbytes < 0){
                    perror("recvfrom");
                    return -1;
                }
                msgbuf[ nbytes ] = '\0';

                msg[ msg_ct ] = ( mdns_msg_raw * ) malloc( sizeof( mdns_msg_raw ) );
                if ( msg[ msg_ct ] == NULL )
                {
                    perror("malloc");
                    return -1;
                }

                mdns_msg_raw *msg_new = msg [ msg_ct ];
                msg_new->msg = ( char * ) malloc( nbytes * sizeof( char ) );
                if ( msg_new == NULL )
                {
                    perror("realloc");
                    return -1;
                }
                memcpy(msg_new->msg, msgbuf, nbytes);
                msg_new->msg_len = nbytes;
                msg_new->info = src;

                if ( ++msg_ct >= msg_alloc )
                {
                    //implement debouncer
                    msg_alloc = msg_ct + 2;
                    msg = ( mdns_msg_raw ** ) realloc( msg, msg_alloc * sizeof(mdns_msg_raw *) );
                    if(msg == NULL)
                    {
                        perror("realloc");
                        return -1;
                    }
                }
                printf("recved\n");
            }
            
            else
            {
                perror("read");
                return -1;
            }
        }

    }

    msg_raw_cnt->msg_raw = msg;

    /*if ( _mdns_exit(fd) )
    {
        return -1;
    }*/
    
    return msg_ct;
}