/* Benchmark.c
 * 
 * An application to automate the benchmarking of post 
 * quantum cryptographic algorithms. The application
 * measures a series of TLS 1.3 handshakes in order to
 * analyse resource usage, security* and power consumption*.
 * 
 * This application was writted as part of the Group
 * Design Project 2022 at the University of Southampton,
 * in partnership with DSTL.
 * 
 * *To be implemented in the future
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

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
#define mbedtls_time            time
#define mbedtls_time_t          time_t
#define mbedtls_fprintf         fprintf
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

/* extra src files */
#include "ssl_server.h"
#include "mbedtls/ssl_ciphersuites.h"
#include "./new_certs.h"
#include "mbedtls/certs.h"

/* application args */
const char *cipherSuiteStrings[] = {"MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 
					"MBEDTLS_TLS_KYBER_ECDSA_WITH_AES_256_GCM_SHA384",
					"MBEDTLS_TLS_SABER_ECDSA_WITH_AES_256_GCM_SHA384",
					"MBEDTLS_TLS_ECDHE_SPHINCS_WITH_AES_256_GCM_SHA384",
					"MBEDTLS_TLS_KYBER_SPHINCS_WITH_AES_256_GCM_SHA384",
					"MBEDTLS_TLS_SABER_SPHINCS_WITH_AES_256_GCM_SHA384",
					"MBEDTLS_TLS_ECDHE_DILITHIUM_WITH_AES_256_GCM_SHA384",
					"MBEDTLS_TLS_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA384",
					"MBEDTLS_TLS_SABER_DILITHIUM_WITH_AES_256_GCM_SHA384"};
const int cipherSuites[] = {MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				MBEDTLS_TLS_KYBER_ECDSA_WITH_AES_256_GCM_SHA384,
				MBEDTLS_TLS_SABER_ECDSA_WITH_AES_256_GCM_SHA384,
				MBEDTLS_TLS_ECDHE_SPHINCS_WITH_AES_256_GCM_SHA384,
				MBEDTLS_TLS_KYBER_SPHINCS_WITH_AES_256_GCM_SHA384,
				MBEDTLS_TLS_SABER_SPHINCS_WITH_AES_256_GCM_SHA384,
				MBEDTLS_TLS_ECDHE_DILITHIUM_WITH_AES_256_GCM_SHA384,
				MBEDTLS_TLS_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA384,
				MBEDTLS_TLS_SABER_DILITHIUM_WITH_AES_256_GCM_SHA384};
const char *certs[] = {TEST_SRV_CRT_EC_PEM,
                       TEST_SRV_CRT_EC_PEM,
                       TEST_SRV_CRT_EC_PEM,
                       TEST_SRV_CRT_SPHINCS_SHAKE256_PEM,
                       TEST_SRV_CRT_SPHINCS_SHAKE256_PEM,
                       TEST_SRV_CRT_SPHINCS_SHAKE256_PEM,
                       TEST_SRV_CRT_DILITHIUM_SHAKE256_PEM,
                       TEST_SRV_CRT_DILITHIUM_SHAKE256_PEM,
			TEST_SRV_CRT_DILITHIUM_SHAKE256_PEM};
const char *keys[] = {TEST_SRV_KEY_EC_PEM,
                      TEST_SRV_KEY_EC_PEM,
                      TEST_SRV_KEY_EC_PEM,
                      TEST_SRV_KEY_SPHINCS_SHAKE256_PEM,
                      TEST_SRV_KEY_SPHINCS_SHAKE256_PEM,
                      TEST_SRV_KEY_SPHINCS_SHAKE256_PEM,
                      TEST_SRV_KEY_DILITHIUM_SHAKE256_PEM,
                      TEST_SRV_KEY_DILITHIUM_SHAKE256_PEM,
			TEST_SRV_KEY_DILITHIUM_SHAKE256_PEM};
char * MsgToClient = "Test Response";

int main(int argc, char *argv[]) {
	if(argc == 2) {
		run_server(certs[atoi(argv[1])], keys[atoi(argv[1])], cipherSuites[atoi(argv[1])], MsgToClient);
	} else {
    	printf("Incorrect arguments supplied\n");
  	}

	return 0;
}
