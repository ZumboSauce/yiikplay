#include <stdio.h>
#include <stdlib.h>
#include "mdns.h"
#include <string.h>

int main(){
    /*int fd;
    init_mdns_addr(&fd);
    mdns_msg_raw_vec msgs_raw;
    int count = mdns_listen(fd, &msgs_raw, 2048, 10.0);
    printf("%d MDNS in\n", count);

    mdns_msg **msgs = malloc ( msgs_raw.raw_ct * sizeof( mdns_msg * ) );
    mdns_qtn_vec qtns_airplay;
    
    mdns_msg_vec mdns_msgs;
    mdns_msgs.msgs = msgs;
    if ( msgs == NULL )
    {
        perror("malloc");
        return -1;
    }
    for ( int i = 0, j = 0; i < count; i++ )
    {
        msgs[i] = malloc ( sizeof( mdns_msg ) );
        if ( msgs[i] == NULL )
        {
            perror("malloc");
            return -1;
        }
        if ( stom( msgs[mdns_msgs.msg_ct++], msgs_raw.msgs_raw[i]->msg ) < 1 )
        {
            memset( msgs[mdns_msgs.msg_ct-1], 0, sizeof( mdns_msg ) );
            mdns_msgs.msg_ct -= 1;
            continue;
        }
    }

    select_q(&mdns_msgs, &qtns_airplay, AIRPLAY_MDNS_SERVICE);

    //int thing = mdns_select(&mdns_msgs, &msgs_raw, AIRPLAY_MDNS_SERVICE);
    printf("%d MDNS selected\n", qtns_airplay.qtn_ct);*/
    char *buf;
    open_cfg( "cfgs/airplay.json", &buf );
    /*
    mdns_msg test;
    test.head.tran_id = 0;
    test.head.flags = 0;
    test.head.qtn = 1;
    test.head.rr = 0;
    test.head.arr = 0;
    test.head.auth_rr = 0;
    mdns_qtn *qtn = &(test.body.qtns[0]);
    qtn->type = 12;
    qtn->name = "cum.tcp.local";
    qtn->cast = 1;
    qtn->class = 1;
    char buf[1024];
    mtos( &test, buf );
    */
}