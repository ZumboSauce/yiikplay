#include <stdio.h>
#include "mdns.h"
#include "airplay_mdns.h"


int main(){
    int fd;
    init_mdns_addr(&fd);
    mdns_msg_raw_vec msgs_raw;
    int count = mdns_listen(fd, &msgs_raw, 2048, 10.0);
    printf("%d MDNS in\n", count);

    mdns_msg **msgs = malloc ( msgs_raw.raw_ct * sizeof( mdns_msg * ) );
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
        if ( strtom( msgs[j++], msgs_raw.msgs_raw[i] ) < 1 )
        {
            j -= 1;
            continue;
        }
    }

    

    //int thing = mdns_select(&mdns_msgs, &msgs_raw, AIRPLAY_MDNS_SERVICE);
    printf("%d MDNS selected\n", count);
}