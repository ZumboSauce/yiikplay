#include <mdns.h>
#include <mdns_types.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int             main()
{
    start_mdns_daemon();
}

int             start_mdns_daemon()
{
    u_char LISTEN = 1;
    mdns_listen( &LISTEN );
}

//preps socket for listening
int             _mdns_listen_init()
{
    //create udp socket
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if ( fd < 0 ) {
        perror("socket");
        return -1;
    }
    
    //enable reusing portsss
    u_int enable_reuseaddr = 1;
    if ( setsockopt( fd, SOL_SOCKET, SO_REUSEADDR, (char*) &enable_reuseaddr, sizeof(enable_reuseaddr)) < 0 )
    {
        perror("reuse addr failed");
        return -1;
    }

    //bind address
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl( INADDR_ANY );
    addr.sin_port = htons( MDNS_NETWORK_PORT );
    if ( bind( fd, (struct sockaddr*) &addr, sizeof(addr) ) < 0 )
    {
        perror("bind");
        return -1;
    }

    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(struct ip_mreq));
    inet_pton(AF_INET, MDNS_NETWORK_ADDRESS, &mreq.imr_multiaddr.s_addr);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if ( setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*) &mreq, sizeof(mreq)) < 0 ) {
        perror("setsockopt");
        return -1;
    }

    return fd;
}

//frees socket after listening
int             _mdns_listen_exit( int fd )
{
    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(struct ip_mreq));
    inet_pton(AF_INET, MDNS_NETWORK_ADDRESS, &mreq.imr_multiaddr.s_addr);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if ( setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char*) &mreq, sizeof(mreq)) < 0 ) {
        perror("setsockopt");
        return -1;
    }
}

int             mdns_process_msg( const u_char *msg )
{
    pthread_t t1;
    int res = pthread_create( &t1, NULL, mdns_msg_init, (void *) msg );
}

//listens to mdns network space
int             mdns_listen( u_char *l )
{
    int fd = _mdns_listen_init();
    if ( fd < -1 )
    {
        return -1;
    }

    while ( *l )
    {
        struct pollfd poll_m = 
        {
            .fd = fd,
            .events = POLLRDNORM
        };

        int t = poll( &poll_m, 1, 5 * 1000 );
        if ( t == -1 )
        {
            perror("poll");
            return -1;
        }

        if ( t && poll_m.revents )
        {
            if ( poll_m.revents & POLLRDNORM )
            {   
                u_char* msgbuf = malloc( 1024 );
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
                
                int nbytes = recvfrom( fd, msgbuf, 1024, 0, (struct sockaddr *) src, &srclen );
                if (nbytes < 0)
                {
                    perror("recvfrom");
                    return -1;
                }

                msgbuf[ nbytes ] = '\0';
                mdns_process_msg( msgbuf );
            }
        }
    }
    _mdns_listen_exit( fd );
}