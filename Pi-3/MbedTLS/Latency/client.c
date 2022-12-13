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
#include "../ssl_client1.h"
#include "mbedtls/ssl_ciphersuites.h"
#include "../new_certs.h"
#include "mbedtls/certs.h"

#define TEST_DURATION	3

/* application args */
const char *server_addr = "127.0.0.1";
const char *cipherSuiteStrings[] = {"MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA256", 
									"MBEDTLS_TLS_KYBER_ECDSA_WITH_AES_256_GCM_SHA256",
									"MBEDTLS_TLS_ECDHE_SPHINCS_WITH_AES_256_GCM_SHA256",
									"MBEDTLS_TLS_KYBER_SPHINCS_WITH_AES_256_GCM_SHA256"};
const int cipherSuites[] = {MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA256,
							MBEDTLS_TLS_KYBER_ECDSA_WITH_AES_256_GCM_SHA256,
							MBEDTLS_TLS_ECDHE_SPHINCS_WITH_AES_256_GCM_SHA256,
							MBEDTLS_TLS_KYBER_SPHINCS_WITH_AES_256_GCM_SHA256
							};
const char *certs[] = {TEST_CA_CRT_EC_PEM,
					   TEST_CA_CRT_EC_PEM,
					   TEST_CA_CRT_SPHINCS_SHAKE256_PEM,
					   TEST_CA_CRT_SPHINCS_SHAKE256_PEM};
char * MsgToServer = "Test Message";


int main() {
	// Initialise Time Structure
	struct timeval begin, end;
	begin.tv_sec = 0;
	begin.tv_usec = 0;
	end.tv_sec = 0;
	end.tv_usec = 0;

    for (int i = 0; i < 4; i++) {
		printf("Cipher Suite: %s\n", cipherSuiteStrings[i]);
		
		// Store the current time of day
		gettimeofday(&begin, 0);
		gettimeofday(&end, 0);
		int counter = 0;

		// Loop for a given number of seconds
		while ((end.tv_sec - begin.tv_sec) < TEST_DURATION) {
			run_client(server_addr, certs[i], cipherSuites[i], MsgToServer);
			counter++;
			gettimeofday(&end, 0);
		}

		run_client(server_addr, certs[i], cipherSuites[i], "Shutdown");

		printf("Handshakes Completed: %d\n\n", counter);
		sleep(5);
	}

  	return 0;
}
