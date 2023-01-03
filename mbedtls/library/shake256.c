#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SHAKE256_C)

#include "mbedtls/shake256.h"
#include "mbedtls/platform_util.h"

#include <string.h>

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf printf
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

#include "mbedtls/timing.h"
HASH_INIT

#define SHAKE256_VALIDATE_RET(cond)                           \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_shake256_BAD_INPUT_DATA )
#define SHAKE256_VALIDATE(cond)  MBEDTLS_INTERNAL_VALIDATE( cond )

// /*
//  * 64-bit integer manipulation macros (big endian)
//  */
// #ifndef GET_UINT64_BE
// #define GET_UINT64_BE(n,b,i)                            \
// {                                                       \
//     (n) = ( (uint64_t) (b)[(i)    ] << 56 )       \
//         | ( (uint64_t) (b)[(i) + 1] << 48 )       \
//         | ( (uint64_t) (b)[(i) + 2] << 40 )       \
//         | ( (uint64_t) (b)[(i) + 3] << 32 )       \
//         | ( (uint64_t) (b)[(i) + 4] << 24 )       \
//         | ( (uint64_t) (b)[(i) + 5] << 16 )       \
//         | ( (uint64_t) (b)[(i) + 6] <<  8 )       \
//         | ( (uint64_t) (b)[(i) + 7]       );      \
// }
// #endif  GET_UINT64_BE 

// #ifndef PUT_UINT64_BE
// #define PUT_UINT64_BE(n,b,i)                            \
// {                                                       \
//     (b)[(i)    ] = (unsigned char) ( (n) >> 56 );       \
//     (b)[(i) + 1] = (unsigned char) ( (n) >> 48 );       \
//     (b)[(i) + 2] = (unsigned char) ( (n) >> 40 );       \
//     (b)[(i) + 3] = (unsigned char) ( (n) >> 32 );       \
//     (b)[(i) + 4] = (unsigned char) ( (n) >> 24 );       \
//     (b)[(i) + 5] = (unsigned char) ( (n) >> 16 );       \
//     (b)[(i) + 6] = (unsigned char) ( (n) >>  8 );       \
//     (b)[(i) + 7] = (unsigned char) ( (n)       );       \
// }
// #endif /* PUT_UINT64_BE */


void mbedtls_shake256_init( mbedtls_shake256_context *ctx )
{
    SHAKE256_VALIDATE( ctx != NULL );

    memset( ctx, 0, sizeof( mbedtls_shake256_context ) );
}

void mbedtls_shake256_free( mbedtls_shake256_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_shake256_context ) );
}

/*
 * SHAKE-256 context setup
 */
int mbedtls_shake256_starts_ret( mbedtls_shake256_context *ctx)
{
    SHAKE256_VALIDATE_RET( ctx != NULL );

    ctx->buff_len = 0;

    return( 0 );
}

/*
 * SHAKE-256 process buffer
 */
int mbedtls_shake256_update_ret( mbedtls_shake256_context *ctx,
                               const unsigned char *input,
                               size_t ilen )
{

    SHAKE256_VALIDATE_RET( ctx != NULL );
    SHAKE256_VALIDATE_RET( ilen == 0 || input != NULL );

    if( ilen == 0 )
        return( 0 );

    *(& ctx -> buffer + ctx -> buff_len ) = ( unsigned char *) malloc ( ilen ) ;
    memcpy( (ctx->buffer + ctx->buff_len), input, ilen);
    ctx->buff_len += ilen;

    return( 0 );
}


/*
 * SHA-512 final digest
 */
int mbedtls_shake256_finish_ret( mbedtls_shake256_context *ctx,
                               unsigned char output[64] )
{

    SHAKE256_VALIDATE_RET( ctx != NULL );
    SHAKE256_VALIDATE_RET( (unsigned char *)output != NULL );

    shake256_d(output, 64, ctx->buffer, (unsigned long long) ctx->buff_len);
    return( 0 );
}

/*
 * output = SHAKE-512( input buffer )
 */
int mbedtls_shake256_ret( const unsigned char *input,
                    size_t ilen,
                    unsigned char output[64])
{

    shake256_d(output, 64, input, (unsigned long long) ilen);
    return( 0 );
}
#endif
