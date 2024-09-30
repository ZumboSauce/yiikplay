#include <stdio.h>
#include "mdns.h"
#include "airplay_mdns.h"


int main(){
    int fd;
    init_mdns_addr(&fd);
    mdns_msg_raw **msgs_raw;
    int count = mdns_listen(fd, &msgs_raw, 2048, 10.0);
    printf("%d MDNS in\n", count);
    mdns_msg **mdns_msgs;
    int thing = mdns_select(&mdns_msgs, msgs_raw, count, AIRPLAY_MDNS_SERVICE);
    printf("%d MDNS selected\n", count);
}