#include "util.h"
#include <stdlib.h>

char            *strlchr( const char *__s, int __c )
{
    while ( *__s != 0 )
    {
        if ( *__s < __c )
        {
            return (char *) __s;
        }
        __s += 1;
    }
    return NULL;
}