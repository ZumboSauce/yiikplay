#ifndef __UTIL__
#define __UTIL__

#ifndef MAKEWORD
    #define MAKEWORD( lb, hb ) ((hb << 8) | lb)
#endif
#define MAKEDWORD(a, b, c, d) ( (d << 24) | (c << 16) | (b << 8) | a )
#define MAX(a,b) ((a) > (b) ? (a) : (b))

#include <stdint.h>

typedef uint8_t u_char;
typedef uint16_t u_short;
typedef uint32_t u_int;

char            *strlchr( const char *__s, int __c );



#endif