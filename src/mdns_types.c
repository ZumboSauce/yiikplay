#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <sys/types.h>

#include <mdns.h>
#include <mdns_types.h>
#include <util.h>

void            addrtoi( char *a, u_int *i )
{
    for ( int k = 3; k >= 0; i++, a++ )
    {
        i += *a << ( 8 * k );
    }
}

void            w_read( int c, char *in, u_short *out )
{
    for ( int i = 0; i < c; i++, in+=sizeof(short), out += sizeof(short) )
    {
        *out = le_makeword( in, sizeof(short) );
    }
}

int             le_makeword( u_char *lb, u_char c  )
{
    int ret = 0;
    for ( int i = 0; i < c; i++ )
    {
        ret = ( ret << 8 ) | *( lb + i );
    }
    return ret;
}

//resolves dns compression
int             dns_cmp_res( char *raw, u_short idx, char *out )
{
    u_short len = raw[idx];
    if( len == 0 )
    {
        out[-1] = '\0';
        return 1;
    }
    else if ( len >= 0xc0 )
    {
        dns_cmp_res( raw, MAKEWORD( raw[idx+1], raw[idx] & DNS_COMPRESSION_MASK ), out );
        return 2;
    }
    else
    {
        strncpy( out, raw + ( idx + 1 ), len );
        out[len] = '.';
        return dns_cmp_res( raw, idx + ( len + 1 ), out + ( len + 1 ) ) + ( len + 1 );
    }
}

int             r_txt_init( char *raw, u_short idx, r_txt *txt, r_tmp *tmp )
{
    u_short datalen = txt->datalen;
    r_txt_f **f = &(txt->data);
    while( datalen > 0 )
    {
        if ( ( *f = malloc( sizeof(r_txt_f) ) ) == NULL )
        {
            perror("malloc");
            return -1;
        }

        datalen -= (*f)->len_f = *( raw + idx++ );
        if ( ( (*f)->f = malloc( (*f)->len_f * sizeof(u_char) ) ) == NULL )
        {
            perror("malloc");
            return -1;
        }

        (*f)->next == NULL;
        memcpy( *f, raw + idx++, (*f)->len_f );
        f = &( (*f)->next );
    }
    return idx;
}

int             r_srv_init( char *raw, u_short idx, r_srv *srv, r_tmp *tmp )
{
    srv->srv = malloc( MDNS_NAME_MAX_LEN * sizeof( u_char ) );
    srv->proto = malloc( MDNS_NAME_MAX_LEN * sizeof( u_char ) );
    srv->name = malloc( MDNS_NAME_MAX_LEN * sizeof( u_char ) );

    char **bufs[] = { &( srv->srv ), &( srv->proto ), &( srv->name ) };

    if( srv->srv == NULL || srv->proto == NULL || srv->tgt == NULL )
    {
        perror("malloc");
        return -1;
    }

    for( int k = 0; k < 3; k++ )
    {
        u_short i = 0, j = 0, len = 0;
        while( tmp->name[j] != '.' && j++ < tmp->len_name )
        {
            (*(bufs[k]))[i++] = tmp->name[j];
        }
        (*(bufs[k]))[i] = '\0';

        char* tmp_buf;
        tmp_buf = *(bufs[k]);
        if ( realloc( *(bufs[k]), ++i ) == NULL )
        {
            perror("realloc");
            return -1;
        }
        j += 1;
    }

    w_read( 3, raw + idx, &( srv->prio ) );
    idx += 6;

    srv->tgt = malloc( MDNS_NAME_MAX_LEN * sizeof(u_char) );
    idx += srv->len_tgt = dns_cmp_res( raw, idx, srv->tgt );
    char *tmp_buf = srv->tgt;
    if ( realloc( srv->tgt, srv->len_tgt ) == NULL )
    {
        perror("realloc");
        return -1;
    }
    return idx + 1;
}

int             r_ptr_init( char *raw, u_short idx, r_ptr *ptr, r_tmp *tmp )
{
    memcpy( ptr, tmp, sizeof( r_tmp ) );
    memcpy( ptr->dom, raw + idx, ptr->datalen );
    return idx + ptr->datalen;
}

int             r_a_init( char *raw, u_short idx, r_a *a, r_tmp *tmp )
{
    memcpy( a, tmp, sizeof( r_tmp ) );
    addrtoi( raw + idx, &( a->addr ) );
    return idx + a->datalen;
}

int             mdns_rr_init( char *raw, u_short idx, mdns_rr *rr )
{
    r_tmp tmp;
    record_type type;
    tmp.name = malloc( 1024 * sizeof( u_char ) );
    if( tmp.name == NULL )
    {
        perror("malloc");
        return -1;
    }
    idx += tmp.len_name = dns_cmp_res( raw, idx, tmp.name );
    char *prev;
    tmp.name = realloc( prev = tmp.name, tmp.len_name * sizeof( char ) );
    if ( tmp.name == NULL )
    {
        perror("realloc");
        free( prev );
        return -1;
    }
    type = tmp.type = le_makeword( raw, 2 );
    WORDSPLIT( le_makeword( raw + idx + 2, 2 ), 1, tmp.class, tmp.flush );
    tmp.ttl = le_makeword( raw + idx + 4, 4 );
    tmp.datalen = le_makeword( raw + idx + 6, 2 );

    short ret;

    switch( type )
    {
        case A:
            if ( ( rr->a = malloc( sizeof( r_a ) ) ) == NULL )
            {
                perror("malloc");
                return -1;
            }
            if ( ( ret = r_a_init( raw, idx, rr->a, &tmp ) ) < 0 )
            {
                return -1;
            }
            return idx + ret;
        case PTR:
            if ( ( rr->ptr = malloc( sizeof( r_ptr ) ) ) == NULL )
            {
                perror("malloc");
                return -1;
            }
            if ( ( ret = r_ptr_init( raw, idx, rr->ptr, &tmp ) ) < 0 )
            {
                return -1;
            }
            return idx + ret;
        case SRV:
            if ( ( rr->srv = malloc( sizeof( r_srv ) ) ) == NULL )
            {
                perror("malloc");
                return -1;
            }
            if ( ( ret = r_srv_init( raw, idx, rr->srv, &tmp ) ) < 0 )
            {
                return -1;
            }
            return idx + ret;
        case TXT:
            if ( ( rr->txt = malloc( sizeof( r_txt ) ) ) == NULL )
            {
                perror("malloc");
                return -1;
            }
            if ( ( ret = r_txt_init( raw, idx, rr->txt, &tmp ) ) < 0 )
            {
                return -1;
            }
            return idx + ret;
        default:
            fprintf( stderr, "%s: DNS record of type %d is not supported\n", __func__, tmp.type );
            return -1;
    }
}

//populates structure as a PTR query
int             q_ptr_init( char *raw, u_short idx, q_ptr *qtn )
{
    qtn->name = malloc( MDNS_NAME_MAX_LEN * sizeof( u_char ) );
    if( qtn->name == NULL )
    {
        perror("malloc");
        return -1;
    }
    idx += qtn->len_name = dns_cmp_res( raw, idx, qtn->name );
    char *prev;
    qtn->name = realloc( prev = qtn->name, qtn->len_name * sizeof( char ) );
    if ( qtn->name == NULL )
    {
        perror("realloc");
        free( prev );
        return -1;
    }
    qtn->type = le_makeword( raw + idx, 2 );
    WORDSPLIT( le_makeword( raw + idx + 2, 2 ), 1, qtn->class, qtn->cast );
    printf("%s\n", qtn->name);
    return idx + 4;
}

//populates mdns_qtn struct according to data in raw
int             mdns_qtn_init( char *raw, u_short idx, mdns_qtn *qtn )
{
    //space here to adapt to query types other than PTR ig ?
    return q_ptr_init( raw, idx, qtn->ptr );
}

//populates mdns_msg struct according to data in raw
void             *mdns_msg_init( void *raw )
{
    printf( "Processing Message\n" );
    //populates header
    u_short idx = 0;
    mdns_msg *msg = malloc( 1 * sizeof( mdns_msg ) );
    w_read( 6, raw + idx, &(msg->head.tran_id) );
    idx += 12;
    
    mdns_qtn *cur = msg->qtn = malloc( 1 * sizeof( mdns_qtn ) );
    if ( cur == NULL )
    {
        perror("malloc");
        //return -1;
    }

    printf("%d\n", msg->head.qtn);
    for ( int i = 0; i < msg->head.qtn; i++ )
    {
        idx += mdns_qtn_init( raw, idx, cur );
        cur = cur->next = malloc( 1 * sizeof( mdns_qtn ) );
        if ( cur == NULL )
        {
            perror("malloc");
            //return -1;
        }
    }

}