/*
 *  SSL server demonstration program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 *
 *  This file is provided under the Apache License 2.0, or the
 *  GNU General Public License v2.0 or later.
 *
 *  **********
 *  Apache License 2.0:
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  **********
 *
 *  **********
 *  GNU General Public License v2.0 or later:
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  **********
 */

#include <math.h>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_time       time
#define mbedtls_time_t     time_t
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif

#include "mbedtls/timing.h"

#if !defined(MBEDTLS_BIGNUM_C) ||    \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_SSL_TLS_C) || \
    !defined(MBEDTLS_SSL_SRV_C) || !defined(MBEDTLS_NET_C) ||     \
    !defined(MBEDTLS_CTR_DRBG_C) ||    \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_FS_IO) || \
    !defined(MBEDTLS_PEM_PARSE_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_CERTS_C and/or MBEDTLS_ENTROPY_C "
           "and/or MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_SRV_C and/or "
           "MBEDTLS_NET_C and/or MBEDTLS_RSA_C and/or "
           "MBEDTLS_CTR_DRBG_C and/or MBEDTLS_X509_CRT_PARSE_C "
           "and/or MBEDTLS_PEM_PARSE_C not defined.\n");
    mbedtls_exit( 0 );
}
#else

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#include "new_certs.h"

// Comment or define GDP_MEM_TEST as required for heap benchmarking
// #define GDP_MEM_TEST
#ifdef GDP_MEM_TEST
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

/*
 * For heap usage estimates, we need an estimate of the overhead per allocated
 * block. ptmalloc2/3 (used in gnu libc for instance) uses 2 size_t per block,
 * so use that as our baseline.
 */
#define MEM_BLOCK_OVERHEAD  ( 2 * sizeof( size_t ) )

/*
 * Size to use for the alloc buffer if MEMORY_BUFFER_ALLOC_C is defined.
 */
#define HEAP_SIZE       (1u << 21)  // 64k

#define MEMORY_MEASURE_INIT                                             \
    size_t max_used, max_blocks, max_bytes;                             \
    size_t prv_used, prv_blocks;                                        \
    mbedtls_memory_buffer_alloc_cur_get( &prv_used, &prv_blocks );      \
    mbedtls_memory_buffer_alloc_max_reset( );

#define MEMORY_MEASURE_PRINT                                            \
    mbedtls_memory_buffer_alloc_max_get( &max_used, &max_blocks );      \
    max_used -= prv_used;                                               \
    max_blocks -= prv_blocks;                                           \
    max_bytes = max_used + MEM_BLOCK_OVERHEAD * max_blocks;             \
    mbedtls_printf( "Heap Usage - %u bytes\n\n", (unsigned) max_bytes );
#endif

#define HTTP_RESPONSE "Test Response"

#define DEBUG_LEVEL 1

#define PRINT_AT_DEBUG_LEVEL(level, msg) \
    if (DEBUG_LEVEL >= level) mbedtls_printf(msg)

int stop = 0;

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

mbedtls_pq_avg_performance run_server(const char *cert, const char *key, const int cipher_suite, char *MsgToClient)
{
    int ret, len;
    mbedtls_net_context listen_fd, client_fd;
    unsigned char buf[1024];
    const char *pers = "ssl_server";

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif

    mbedtls_net_init( &listen_fd );
    mbedtls_net_init( &client_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    
#if defined(MBEDTLS_PEFORMANCE)
    mbedtls_pq_performance performance;
    /*performance.handshake = 0;
    performance.sphincs_sign,
    performance.dilithium_sign = 0;
    performance.kyber_dec = 0;
    performance.kyber_genkey = 0;
    performance.write_client_hello = 0;
    performance.parse_server_hello = 0;
    performance.parse_server_certificate = 0;
    performance.parse_server_key_exchange = 0;
    performance.parse_server_hello_done = 0;
    performance.write_client_key_exchange = 0;
    performance.write_client_change_cipher = 0;
    performance.write_client_finish = 0;
    performance.parse_server_change_cipher = 0;
    performance.parse_server_finish = 0;
    performance.hashs = 0;*/
    
    /*mbedtls_printf( "  . Performance Data: %.3f,%.3f,%.3f,%.3f,%.3f,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%.3f\n",
            performance.handshake,
            performance.sphincs_sign,
            performance.dilithium_sign,
            performance.kyber_dec,
            performance.kyber_genkey,
            performance.parse_client_hello,
            performance.write_server_hello,
            performance.write_server_certificate,
            performance.write_server_key_exchange,
            performance.write_server_hello_done,
            performance.parse_client_key_exchange,
            performance.parse_client_change_cipher,
            performance.parse_client_finish,
            performance.write_server_change_cipher,
            performance.write_server_finish,
            performance.hashs
        );*/
    
    mbedtls_pq_avg_performance avg_performance;
	ssl.performance = &performance;
    avg_performance.handshake_x = 0;
    avg_performance.handshake_x2 = 0;
    avg_performance.kyber_dec_x = 0;
    avg_performance.kyber_dec_x2 = 0;
    avg_performance.sphincs_sign_x = 0;
    avg_performance.sphincs_sign_x2 = 0;
    avg_performance.kyber_genkey_x = 0;
    avg_performance.kyber_genkey_x2 = 0;
    avg_performance.count = 0;
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && defined(GDP_MEM_TEST)
    unsigned char alloc_buf[HEAP_SIZE] = { 0 };
    mbedtls_memory_buffer_alloc_init( alloc_buf, sizeof( alloc_buf ) );
#endif

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init( &cache );
#endif
    mbedtls_x509_crt_init( &srvcert );
    mbedtls_pk_init( &pkey );
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( DEBUG_LEVEL );
#endif

    /*
     * 1. Load the certificates and private RSA key
     */
    PRINT_AT_DEBUG_LEVEL( 1, "\n  . Loading the server cert. and key..." );
    fflush( stdout );

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
     * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
     */
    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) cert, strlen(cert)+1);
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        goto exit;
    }

    // ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *)TEST_ALL_CA_CRTS, strlen(TEST_ALL_CA_CRTS)+1);
    // if( ret != 0 )
    // {
    //     mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
    //     goto exit;
    // }

    ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) key, strlen(key)+1, NULL, 0 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
        goto exit;
    }

    PRINT_AT_DEBUG_LEVEL( 1, " ok\n" );

    /*
     * 2. Setup the listening TCP socket
     */
    PRINT_AT_DEBUG_LEVEL( 1, "  . Bind on https://localhost:4433/ ..." );
    fflush( stdout );

    if( ( ret = mbedtls_net_bind( &listen_fd, NULL, "4433", MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_bind returned %d\n\n", ret );
        goto exit;
    }

    PRINT_AT_DEBUG_LEVEL( 1, " ok\n" );

    /*
     * 3. Seed the RNG
     */
    PRINT_AT_DEBUG_LEVEL( 1, "  . Seeding the random number generator..." );
    fflush( stdout );

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    PRINT_AT_DEBUG_LEVEL( 1, " ok\n" );

    /*
     * 4. Setup stuff
     */
    PRINT_AT_DEBUG_LEVEL( 1, "  . Setting up the SSL data...." );
    fflush( stdout );

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_SERVER,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache( &conf, &cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set );
#endif

    mbedtls_ssl_conf_ciphersuites_for_version(&conf, (int[]) {cipher_suite}, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

    mbedtls_ssl_conf_ca_chain( &conf, srvcert.next, NULL );
    if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &srvcert, &pkey ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }

    PRINT_AT_DEBUG_LEVEL( 1, " ok\n" );

reset:
#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    mbedtls_net_free( &client_fd );

    mbedtls_ssl_session_reset( &ssl );

    /*
     * 3. Wait until a client connects
     */
    PRINT_AT_DEBUG_LEVEL( 1, "  . Waiting for a remote connection ..." );
    fflush( stdout );

    if( ( ret = mbedtls_net_accept( &listen_fd, &client_fd,
                                    NULL, 0, NULL ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_accept returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_set_bio( &ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

    PRINT_AT_DEBUG_LEVEL( 1, " ok\n" );

    /*
     * 5. Handshake
     */
    PRINT_AT_DEBUG_LEVEL( 1, "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );
	struct mbedtls_timing_hr_time handshaketimer;
	(void)mbedtls_timing_get_timer(&handshaketimer, 1);
#ifdef GDP_MEM_TEST
    MEMORY_MEASURE_INIT;
#endif
    while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret );
            goto reset;
        }
    }
#ifdef GDP_MEM_TEST
    MEMORY_MEASURE_PRINT;
#endif
    PRINT_AT_DEBUG_LEVEL( 1, " ok\n");

    if (DEBUG_LEVEL >= 1) {
        mbedtls_printf( "  . Cipher Suite Used: %s\n", mbedtls_ssl_get_ciphersuite( &ssl ) );
    }

#if defined(MBEDTLS_PEFORMANCE)
	ssl.performance->handshake = mbedtls_timing_get_timer(&handshaketimer, 0);
	
    if (DEBUG_LEVEL >= 1) {
        mbedtls_printf( "  . Performance Data: %.3f,%.3f,%.3f,%.3f,%.3f,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%.3f\n",
            performance.handshake,
            performance.sphincs_sign,
            performance.dilithium_sign,
            performance.kyber_dec,
            performance.kyber_genkey,
            performance.parse_client_hello,
            performance.write_server_hello,
            performance.write_server_certificate,
            performance.write_server_key_exchange,
            performance.write_server_hello_done,
            performance.parse_client_key_exchange,
            performance.parse_client_change_cipher,
            performance.parse_client_finish,
            performance.write_server_change_cipher,
            performance.write_server_finish,
            performance.hashs
        );
    }

    // Update average performance metrics
    avg_performance.handshake_x += performance.handshake;
    avg_performance.handshake_x2 += pow(performance.handshake, 2);
    avg_performance.kyber_dec_x += performance.kyber_dec;
    avg_performance.kyber_dec_x2 += pow(performance.kyber_dec, 2);
    avg_performance.sphincs_sign_x += performance.sphincs_sign;
    avg_performance.sphincs_sign_x2 += pow(performance.sphincs_sign, 2);
    avg_performance.kyber_genkey_x += performance.kyber_genkey;
    avg_performance.kyber_genkey_x2 += pow(performance.kyber_genkey, 2);
    avg_performance.count += 1;
    //printf("Key gen: %.3f ", performance.kyber_genkey);
   // printf("Key decap: %.3f \n", performance.kyber_dec);
    
#endif	
    

    /*
     * 6. Read the HTTP Request
     */
    PRINT_AT_DEBUG_LEVEL(1, "  < Read from client:" );
    fflush( stdout );

    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = mbedtls_ssl_read( &ssl, buf, len );

        if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
            continue;

        if( ret <= 0 )
        {
            switch( ret )
            {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    mbedtls_printf( " connection was closed gracefully\n" );
                    break;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    mbedtls_printf( " connection was reset by peer\n" );
                    break;

                default:
                    mbedtls_printf( " mbedtls_ssl_read returned -0x%x\n", -ret );
                    break;
            }

            break;
        }

        if (strcmp((char *) buf, "Shutdown") == 0) {
            stop = 1;
        }

        len = ret;
        if (DEBUG_LEVEL >= 1) {
            mbedtls_printf( " %d bytes read\n  < %s\n", len, (char *) buf );
        }

        if( ret > 0 )
            break;
    }
    while( 1 );

    /*
     * 7. Write the 200 Response
     */
    PRINT_AT_DEBUG_LEVEL(1, "  > Write to client:" );
    fflush( stdout );

    if (stop == 1) {
        len = sprintf( (char *) buf, "Shutdown Confirmed");
    } else {
        len = sprintf( (char *) buf, MsgToClient);
    }

    while( ( ret = mbedtls_ssl_write( &ssl, buf, len ) ) <= 0 )
    {
        if( ret == MBEDTLS_ERR_NET_CONN_RESET )
        {
            mbedtls_printf( " failed\n  ! peer closed the connection\n\n" );
            goto reset;
        }

        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
            goto exit;
        }
    }

    len = ret;
    if (DEBUG_LEVEL >= 1) {
        mbedtls_printf( " %d bytes written\n  > %s\n", len, (char *) buf ); 
    }
    PRINT_AT_DEBUG_LEVEL(1, "  . Closing the connection..." );

    while( ( ret = mbedtls_ssl_close_notify( &ssl ) ) < 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret );
            goto reset;
        }
    }

    PRINT_AT_DEBUG_LEVEL(1, " ok\n" );

    ret = 0;

    if (stop == 0) {
        PRINT_AT_DEBUG_LEVEL(1, "\n");
        goto reset;
    } else {
        stop = 0;
    }

exit:

#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    mbedtls_net_free( &client_fd );
    mbedtls_net_free( &listen_fd );

    mbedtls_x509_crt_free( &srvcert );
    mbedtls_pk_free( &pkey );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free( &cache );
#endif
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

#if defined(_WIN32)
    mbedtls_printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && defined(GDP_MEM_TEST)
    mbedtls_memory_buffer_alloc_free();
#endif

    return avg_performance;
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_CERTS_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_SSL_TLS_C && MBEDTLS_SSL_SRV_C && MBEDTLS_NET_C &&
          MBEDTLS_RSA_C && MBEDTLS_CTR_DRBG_C && MBEDTLS_X509_CRT_PARSE_C
          && MBEDTLS_FS_IO && MBEDTLS_PEM_PARSE_C */
