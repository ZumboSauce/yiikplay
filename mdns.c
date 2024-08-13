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

int     init_mdns_addr()
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
    int fd = (int)socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    
    //enable reusing ports
    u_int enable_reuseaddr = 1;
    if ( setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*) &enable_reuseaddr, sizeof(enable_reuseaddr)) < 0) {
        perror("reuse addr failed");
        return -1;
    }

    //bind address
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(MDNS_NETWORK_PORT);
    if ( bind(fd, (struct sockaddr*) &addr, sizeof(addr)) < 0 ) {
        perror("bind");
        return -1;
    }
}

int     _mdns_join(int fd)
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

int     _mdns_exit(int fd)
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

int     _mdns_name_res(u_char* msg, char* name, u_short idx)
{
    u_short label_len = msg[idx];

    if( label_len == 0 )
    {
        name[0] = '\0';
        return 1;
    }
    else if ( (label_len >> 6) == MDNS_POINTER )
    {
        idx = MAKEWORD( msg[idx + 1], label_len & (~(MDNS_POINTER << 6)) );
        _mdns_name_res(msg, name, idx);
        return 2;
    }
    else
    {
        strncpy(name, msg + idx + 1, label_len);
        return label_len + _mdns_name_res(msg, name + label_len, idx + label_len + 1);
    }
}

int     _strtomhead(char *msg, mdns_head *head){
    head->tran_id   = MAKEWORD(msg[1], msg[0]);
    head->flags     = MAKEWORD(msg[3], msg[2]);
    head->qtn       = MAKEWORD(msg[5], msg[4]);
    head->rr        = MAKEWORD(msg[7], msg[6]);
    head->auth_rr   = MAKEWORD(msg[9], msg[8]);
    head->add_rr    = MAKEWORD(msg[11], msg[10]);
}

int     strtom(char* msg, mdns_msg* mdns){
    _strtomhead(msg, mdns->head);

    mdns->body->qtns = (mdns_qtn **) malloc( mdns->head->qtn * sizeof(mdns_qtn *) );
    mdns->body->rrs = (mdns_rr **) malloc( mdns->head->rr * sizeof(mdns_rr *) );

    u_short msg_idx = MDNS_MSG_HEADER_LEN; 

    for (int i = 0; i < mdns->head->qtn; i++)
    {
        //LOOK UP IF OVER REFERENCING IS LESS EFFICIENT
        mdns_qtn *qtn = (mdns_qtn *) malloc ( sizeof(mdns_qtn) );
        mdns->body->qtns[i] = qtn;

        msg_idx += _mdns_name_res( msg, qtn->name, msg_idx);

        qtn->name_len    = strlen(qtn->name);
        qtn->type       = MAKEWORD( msg[msg_idx + 1], msg[msg_idx]);
        u_short cqu     = MAKEWORD( msg[msg_idx + 3], msg[msg_idx + 2]);
        qtn->class      = cqu & ( ~ (1 << 15) );
        qtn->cast       = cqu & ( 1 << 15 );

        msg_idx += 4;
    }

    for (int i = 0; i < mdns->head->rr; i++)
    {
        mdns_rr *rr = (mdns_rr *) malloc ( sizeof(mdns_rr) );
        mdns->body->rrs[i] = rr;

        msg_idx += _mdns_name_res( msg, rr->name, msg_idx );

        rr->name_len     = strlen(rr->name);
        rr->type        = MAKEWORD( msg[msg_idx + 1], msg[msg_idx]);
        u_short cqu     = MAKEWORD( msg[msg_idx + 3], msg[msg_idx + 2]);
        rr->class       = cqu & ( ~ (1 << 15) );
        rr->flush       = cqu & ( 1 << 15 );
        rr->ttl         = MAKEDWORD( msg[msg_idx + 7], msg[msg_idx + 6], msg[msg_idx + 5], msg[msg_idx + 4]);
        //WRONG INDEX??
        rr->dom_len     = MAKEWORD( msg[msg_idx + 5], msg[msg_idx + 4] );
        
        msg_idx += 6;
        msg_idx += _mdns_name_res( msg, rr->dom, msg_idx);
    }
}

int     mdns_listen(int fd, mdns_msg ***msg, double listen_time)
{

    if ( _mdns_join(fd) < -1 )
    {
        return -1;
    }

    mdns_msg **msg_local;

    u_short msg_cnt = 0, msg_alloc = 2;
    time_t start, cur;
    start = cur = time(NULL);

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
                
                printf("%d\n", nbytes);

                msg_local[ msg_cnt ] = (mdns_qtn *) malloc(sizeof(mdns_qtn));
                if ( msg_local[ msg_cnt ] == NULL )
                {
                    perror("malloc");
                    return -1;
                }

                if ( ++msg_cnt >= msg_alloc )
                {
                    //implement debouncer
                    msg_alloc = msg_cnt + 2;
                    msg_local = ( mdns_qtn ** ) realloc( msg_local, msg_alloc * sizeof(mdns_qtn *) );
                    if(msg_local == NULL)
                    {
                        perror("realloc");
                        return -1;
                    }
                }
            }
            
            else
            {
                perror("read");
                return -1;
            }
        }
    }

    *msg = msg_local;

    if ( _mdns_exit(fd) )
    {
        return -1;
    }
    
    return msg_cnt;
}