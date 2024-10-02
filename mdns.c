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
int             dcmptostr( u_char* msg, char* name, u_short idx )
{
    if( msg[idx] == 0 )
    {
        name[0] = '\0';
        return 1;
    }
    else if ( msg[idx] >= 0xc0 )
    {
        dcmptostr( msg, name, MAKEWORD( msg[idx+1], msg[idx] & ( 0b00111111 ) ) );
        return 2;
    }
    else
    {
        strncpy( name, 1 + msg + idx, msg[idx] );
        return 1 + msg[idx] + dcmptostr( msg, name + msg[idx], 1 + msg[idx] + idx );
    }
}

//converts string ptr rr to struct
inline int      _r_stoptr( rr_ptr *ptr, char **msg, char *msg_o )
{
    u_short data_len = MAKEWORD( (*msg)[9], (*msg)[8] );
    char dom[256];
    dcmptostr(msg_o, dom, ( *msg + 10 ) - msg_o );
    ptr->dom_len    = strlen(dom);
    ptr->dom        = malloc( ptr->dom_len * sizeof(char) );
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
inline int      _r_stoa( rr_a *a, char **msg, char *msg_o )
{
    u_short data_len = MAKEWORD( (*msg)[9], (*msg)[8] );
    a->addr         = MAKEDWORD( (*msg)[10], (*msg)[11], (*msg)[12], (*msg)[13] );
    *msg += 14 * sizeof(u_char);
    return 1;
}

//converts string srv rr to struct
inline int      _r_stosrv( rr_srv *srv, char **msg, char *msg_o )
{
    char **labels = malloc( 3 * sizeof( char * ) );

    char *name = srv->name;
    for( int i = 0; i < 3; i++ )
    {
        char *sub = strchr( name + 1, '_' );
        if( sub == NULL )
        {
            labels[i] = malloc( strlen(name) * sizeof( char ) );
            strcpy( labels[i], name );
        }
        u_short label_len = sub - name;
        labels[i] = malloc( label_len * sizeof( char ) );
        strncpy( labels[i], name, label_len - 1 );
        labels[i][label_len] = '\0';
        name += label_len;
    }

    srv->srv            = labels[0];
    srv->proto          = labels[1];
    srv->n              = labels[2];
    u_short data_len    = MAKEWORD( (*msg)[9], (*msg)[8] );
    srv->prio           = MAKEWORD( (*msg)[11], (*msg)[10] );
    srv->wgt            = MAKEWORD( (*msg)[13], (*msg)[12] );
    srv->port           = MAKEWORD( (*msg)[15], (*msg)[14] );
    char tgt[256];
    srv->tgt_len        = dcmptostr( msg_o, tgt, ( *msg + 16 ) - msg_o );
    srv->tgt            = malloc( srv->tgt_len * sizeof(char) );
    strcpy( srv->tgt, tgt );
    *msg += 16 + srv->tgt_len;
    return 1;
}

//converts string txt rr to struct
inline int      _r_stotxt( rr_txt *txt, char **msg, char *msg_o )
{
    u_short data_len    = MAKEWORD( (*msg)[9], (*msg)[8] );
    
    char *idx = 10 + *msg;
    *msg += 10 + data_len;
    txt->data  = malloc( sizeof( rr_txt_dat ) );
    if( txt->data == NULL )
    {
        perror("malloc");
        return -1;
    }

    rr_txt_dat *cur = txt->data;
    while ( idx < *msg )
    {
        cur->k_len = *idx;
        cur->k = malloc( *idx * sizeof(char) );
        strncpy( cur->k, idx + 1, *idx );
        idx += *idx + 1;
        cur->next  = malloc( sizeof( rr_txt_dat ) );
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
    base->name          = malloc( base->name_len * sizeof(char) );
    if( base->name == NULL )
    {
        perror("malloc");
        return -1;
    }
    strcpy( base->name, name );
    base->type          = type;
    u_short cqu         = MAKEWORD( (*msg)[3], (*msg)[2] );
    base->class         = cqu & ( ~ (1 << 15) );
    base->flush         = cqu >> 15;
    base->ttl           = MAKEDWORD( (*msg)[7], (*msg)[6], (*msg)[5], (*msg)[4] );
    return 1;
}

//converts string mdns qtn to struct
int             _stomrr( mdns_rr *rr, char **msg, char *msg_o )
{
    char name[MDNS_NAME_MAX_LEN];
    *msg += dcmptostr( msg_o, name, msg_o - *msg );
    u_short type = MAKEWORD( *(*msg + 1), **msg );

    _mdns_rr_prep( ( rr_base * ) &(rr), name, type, msg );

    switch ( type )
    {
        case DNS_RR_PTR:
            return _r_stoptr( &(rr->ptr), msg, msg_o );
            break;
        case DNS_RR_A:
            return _r_stoa( &(rr->a), msg, msg_o );
            break;
        case DNS_RR_SRV:
            return _r_stosrv( &(rr->srv), msg, msg_o );
            break;
        case DNS_RR_TXT:
            return _r_stotxt( &(rr->txt), msg, msg_o );
            break;
        default:
            fprintf(stderr, "Error: DNS record of type %d not supported\n", type);
            return -1;
    }
}

//converts string mdns qtn to struct
int              _stomqtn( mdns_qtn *qtn, char **msg, char *msg_o )
{
    char name[MDNS_NAME_MAX_LEN];
    *msg += dcmptostr( msg_o, name, *msg - msg_o );
    u_char type = MAKEWORD( *(*msg + 1), **msg );

    qtn->name_len   = strlen( name );
    qtn->name       = malloc( qtn->name_len * sizeof(char) );
    if( qtn->name == NULL )
    {
        perror("malloc");
        return -1;
    }
    strcpy( qtn->name, name );

    qtn->type       = type;
    u_short cqu     = MAKEWORD( (*msg)[3], (*msg)[2]);
    qtn->class      = cqu & ( ~ (1 << 15) );
    qtn->cast       = cqu >> 15 ;
    *msg += 4;
    return 1;
}

//extracts header from string mdns message
inline void     _stomhead(char **msg, mdns_head *head)
{
    
    head->tran_id   = MAKEWORD( (*msg)[1], (*msg)[0] );
    head->flags     = MAKEWORD( (*msg)[3], (*msg)[2] );
    head->qtn       = MAKEWORD( (*msg)[5], (*msg)[4] );
    head->rr        = MAKEWORD( (*msg)[7], (*msg)[6] );
    head->auth_rr   = MAKEWORD( (*msg)[9], (*msg)[8] );
    head->arr    = MAKEWORD( (*msg)[11], (*msg)[10] );
    *msg += 12;
}

//converts string mdns message to struct
int             stom( mdns_msg *mdns, char *raw )
{
    char *raw_o = raw;
    _stomhead( &raw, &( mdns->head ) ); 

    mdns->body.qtns = malloc ( mdns->head.qtn * sizeof( mdns_qtn ) );
    mdns->body.rrs = malloc ( mdns->head.rr * sizeof( mdns_rr ) );
    mdns->body.arrs = malloc ( mdns->head.arr * sizeof( mdns_rr ) );

    for ( int i = 0; i < mdns->head.qtn; i++ )
    {
        if ( _stomqtn( &( mdns->body.qtns[i] ), &raw, raw_o ) < 1 )
        {
            fprintf(stderr, "Error: MDNS question processing\n");
            return -1;
        }
    }

    for ( int i = 0; i < mdns->head.rr; i++ )
    {
        if ( _stomrr( &( mdns->body.rrs[i] ), &raw, raw_o ) < 1 )
        {
            fprintf(stderr, "Error: MDNS ressource record processing\n");
            return -1;
        }
    }

    for ( int i = 0; i < mdns->head.arr; i++ )
    {
        if ( _stomrr( &( mdns->body.arrs[i] ), &raw, raw_o ) < 1 )
        {
            fprintf(stderr, "Error: MDNS additional ressource record processing\n");
            return -1;
        }
    }

    return 1;
}

//filters mdns messages
int             select_q(mdns_msg_vec *msgs, mdns_qtn_vec *qtns, char* srv)
{
    u_short alloc = 0;
    for ( int i = 0; i < msgs->msg_ct; i++ )
    {
        mdns_msg *msg = msgs->msgs[i];
        for ( int j = 0; j < msg->head.qtn; j++ )
        {
            if ( !strcmp ( msg->body.qtns[j].name, srv ) )
            {
                if ( qtns->qtn_ct >= alloc )
                {
                    alloc = qtns->qtn_ct + 2;
                    qtns->qtns = realloc( qtns->qtns, alloc * sizeof( mdns_qtn * ) );
                    if ( qtns->qtns == NULL )
                    {
                        perror("realloc");
                        return -1;
                    }
                }
                memcpy( qtns->qtns + qtns->qtn_ct++, &( msg->body.qtns[j] ), sizeof( mdns_qtn * ) );
            }
        }
    }
    return qtns->qtn_ct;
}

//listens to mdns network and stores all messages
int             mdns_listen(int fd, mdns_msg_raw_vec *raw_msgs, int buflen, double listen_time)
{
    if ( _mdns_join(fd) < -1 )
    {
        return -1;
    }

    u_short msg_ct = 0, msg_alloc = 2;
    time_t start, cur;
    start = cur = time(NULL);
    raw_msgs->msgs_raw = malloc( msg_alloc * sizeof(mdns_msg_raw *) );

    while ( difftime(cur, start) < (double)listen_time )
    {
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
                u_char* msgbuf = malloc(MDNS_MSG_BUF_LEN);
                if (msgbuf == NULL)
                {
                    perror("malloc");
                    return -1;
                }

                struct sockaddr_in *src = malloc(sizeof(struct sockaddr_in));
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

                if ( msg_ct >= msg_alloc )
                {
                    //TODO implement debouncer
                    msg_alloc = msg_ct + 2;
                    raw_msgs->msgs_raw = ( mdns_msg_raw ** ) realloc( raw_msgs->msgs_raw, msg_alloc * sizeof(mdns_msg_raw *) );
                    if(raw_msgs->msgs_raw == NULL)
                    {
                        perror("realloc");
                        return -1;
                    }
                }

                mdns_msg_raw *m = raw_msgs->msgs_raw[msg_ct++] = malloc( sizeof( mdns_msg_raw ) );
                if ( m == NULL )
                {
                    perror("malloc");
                    return -1;
                }
                m->msg = malloc( nbytes * sizeof( char ) );
                if ( m->msg == NULL )
                {
                    perror("realloc");
                    return -1;
                }
                memcpy( m->msg, msgbuf, nbytes );
                m->msg_len = nbytes;
                m->info = src;

                printf("recved\n");
            }
            
            else
            {
                perror("read");
                return -1;
            }
        }
    }
    raw_msgs->raw_ct = msg_ct;
    return msg_ct;
}