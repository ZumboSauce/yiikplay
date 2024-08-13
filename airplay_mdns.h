#ifndef __AIRPLAY_MDNS__
#define __AIRPLAY_MDNS__

#include "mdns.h"

#define AIRPLAY_MDNS_SERVICE "_airplay_tcplocal"

int _airplay_valid_mdns_query_header(mdns_qry *query);

#endif