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
#include "mbedtls/ssl.h"

#define TEST_SIZE	50

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
	printf("Test Configuration:\nServer Address - %s\nRepeats - %d\n\n", server_addr, TEST_SIZE);

    for (int i = 0; i < 4; i++) {
		printf("Testing %s...\n\n", cipherSuiteStrings[i]);
		
		//Wait for server to start
		sleep(2);
		
		mbedtls_pq_performance avg_performance;
		int handshake_count = 0;

		// Loop for a given number of handshakes
		for (int j = 0; j < TEST_SIZE; j++) {
			mbedtls_pq_performance new_data = run_client(server_addr, certs[i], cipherSuites[i], MsgToServer);
			handshake_count++;

			// Calculate new average performance metrics
			if (handshake_count == 1) {
				avg_performance = new_data;
			} else {
				avg_performance.handshake = ((avg_performance.handshake * (handshake_count - 1)) + new_data.handshake) / handshake_count;
				avg_performance.sphincs_verify = ((avg_performance.sphincs_verify * (handshake_count - 1)) + new_data.sphincs_verify) / handshake_count;
				avg_performance.kyber_enc = ((avg_performance.kyber_enc * (handshake_count - 1)) + new_data.kyber_enc) / handshake_count;
			}
		}

		// Shutdown the server
		run_client(server_addr, certs[i], cipherSuites[i], "Shutdown");

		printf("Performance Measurements:\n");
		printf("Handshake Latency - %d ms\n", avg_performance.handshake);
		printf("Certificate Verification - %d ms\n", avg_performance.sphincs_verify);
		printf("Key Encapsulation - %d ms\n\n", avg_performance.kyber_enc);
	}

  	return 0;
}
