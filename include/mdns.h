#ifndef __MDNS_H__
#define __MDNS_H__

#include <sys/types.h>

#define     MDNS_NETWORK_ADDRESS "224.0.0.251"
#define     MDNS_NETWORK_PORT 5353

int             start_mdns_daemon();
int             _mdns_listen_init();
int             _mdns_listen_exit( int fd );
int             mdns_listen( u_char *l );

#endif