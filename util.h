#ifndef __UTIL__
#define __UTIL__

#ifndef MAKEWORD
    #define MAKEWORD(lb, hb) ((hb << 8) | lb)
#endif
#define MAKEDWORD(a, b, c, d) ( (d << 24) | (c << 16) | (b << 8) | a )
#define MAX(a,b) ((a) > (b) ? (a) : (b))

#ifdef _WIN32
    #include <stdint.h>
#endif

#define u_char uint8_t
#define u_short uint16_t
#define u_int uint32_t



#endif