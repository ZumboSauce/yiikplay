#include <stdio.h>
#include "mdns.h"
#include "airplay_mdns.h"


int main(){
    int fd = init_mdns_addr();
    mdns_msg **msgs;
    //int count = mdns_listen(fd, &msgs, 15.0);
    //printf("%d\n", count);
}