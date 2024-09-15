#include <stdio.h>
#include "mdns.h"
#include "airplay_mdns.h"


int main(){
    int fd;
    init_mdns_addr(&fd);
    mdns_msg_raw_ct msg_raw;
    int count = mdns_listen(fd, &msg_raw, 2048, 15.0);
    printf("%d\n", count);
}