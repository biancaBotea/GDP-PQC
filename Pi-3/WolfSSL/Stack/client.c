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

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* extra src files */
#include "../client-pq-tls13.h"

/* application args */
char *server_addr = "127.0.0.1";
char *cert_file_paths[] = {"../../Certs/ca-ecc-cert.pem",
                           "../../Certs/falcon_level1_root_cert.pem", 
                           "../../Certs/falcon_level5_root_cert.pem",
                           "../../Certs/dilithium_level2_root_cert.pem",
                           "../../Certs/dilithium_level3_root_cert.pem",
                           "../../Certs/dilithium_level5_root_cert.pem"};
char *sigSchemeNames[] = {"ECDSA", 
                          "Falcon Level 1", 
                          "Falcon Level 5", 
                          "Dilithium 2", 
                          "Dilithium 3", 
                          "Dilithium 5"};
int kem[] = {WOLFSSL_ECC_SECP256R1, 
             WOLFSSL_KYBER_LEVEL1,
             WOLFSSL_KYBER_LEVEL3,
             WOLFSSL_KYBER_LEVEL5,
             WOLFSSL_SABER_LEVEL1,
             WOLFSSL_SABER_LEVEL3,
             WOLFSSL_SABER_LEVEL5};
char *kemNames[] = {"ECDHE",
                    "Kyber Level 1",
                    "Kyber Level 3",
                    "Kyber Level 5",
                    "Saber Level 1",
                    "Saber Level 3",
                    "Saber Level 5"};
char * MsgToServer = "";


int main(int argc, char *argv[]) {
	if(argc == 3) {
		run_client(server_addr, cert_file_paths[atoi(argv[1])], kem[atoi(argv[2])], "shutdown", 1);
	} else {
    	printf("Incorrect arguments supplied\n");
	}

	return 0;
}
