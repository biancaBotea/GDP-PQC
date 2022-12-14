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
#include "../ssl_server.h"
#include "mbedtls/ssl_ciphersuites.h"
#include "../new_certs.h"
#include "mbedtls/certs.h"

/* application args */
const char *cipherSuiteStrings[] = {"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA256", 
                                    "TLS_KYBER_ECDSA_WITH_AES_256_GCM_SHA256",
                                    "TLS_ECDHE_SPHINCS_WITH_AES_256_GCM_SHA256",
                                    "TLS_KYBER_SPHINCS_WITH_AES_256_GCM_SHA256",
                                    "MBEDTLS_TLS_ECDHE_DILITHIUM_WITH_AES_256_GCM_SHA256",
									"MBEDTLS_TLS_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA256"};
const int cipherSuites[] = {MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA256,
                            MBEDTLS_TLS_KYBER_ECDSA_WITH_AES_256_GCM_SHA256,
                            MBEDTLS_TLS_ECDHE_SPHINCS_WITH_AES_256_GCM_SHA256,
                            MBEDTLS_TLS_KYBER_SPHINCS_WITH_AES_256_GCM_SHA256,
                            MBEDTLS_TLS_ECDHE_DILITHIUM_WITH_AES_256_GCM_SHA256,
							MBEDTLS_TLS_KYBER_DILITHIUM_WITH_AES_256_GCM_SHA256};
const char *certs[] = {TEST_SRV_CRT_EC_PEM,
                       TEST_SRV_CRT_EC_PEM,
                       TEST_SRV_CRT_SPHINCS_SHAKE256_PEM,
                       TEST_SRV_CRT_SPHINCS_SHAKE256_PEM,
                       TEST_SRV_CRT_DILITHIUM_SHAKE256_PEM,
					   TEST_SRV_CRT_DILITHIUM_SHAKE256_PEM};
const char *keys[] = {TEST_SRV_KEY_EC_PEM,
                      TEST_SRV_KEY_EC_PEM,
                      TEST_SRV_KEY_SPHINCS_SHAKE256_PEM,
                      TEST_SRV_KEY_SPHINCS_SHAKE256_PEM,
                      TEST_SRV_KEY_DILITHIUM_SHAKE256_PEM,
					  TEST_SRV_KEY_DILITHIUM_SHAKE256_PEM};
char * MsgToClient = "Test Response";

int main() {
    struct timeval begin, end;
    begin.tv_sec = 0;
    begin.tv_usec = 0;
    end.tv_sec = 0;
    end.tv_usec = 0;
    
    for (int i = 0; i < 6; i++) {
        printf("Testing %s...\n\n", cipherSuiteStrings[i]);

        //Wait for port to become available on slower devices
        sleep(1);

        // Measure cpu stats for power calculation pre handshake
        FILE *fileStream; 
        char fileText1 [100];
        fileStream = fopen ("/proc/stat", "r"); 
        fgets (fileText1, 100, fileStream); 
        fclose(fileStream);

        run_server(certs[i], keys[i], cipherSuites[i], MsgToClient);

        // Measure and process cpu stats for power calculations post handshake
        char fileText2 [100];
        fileStream = fopen ("/proc/stat", "r"); 
        fgets (fileText2, 100, fileStream); 
        fclose(fileStream);

        char * fileText1Split = strtok(fileText1, " ");
        fileText1Split = strtok(NULL, " ");
        int cpuValues1[4];
        int k = 0;
        for (k = 0; k < 4; k++) {
            cpuValues1[k] = atoi(fileText1Split);
            fileText1Split = strtok(NULL, " ");
        }

        int cBusy1 = cpuValues1[0] + cpuValues1[1] + cpuValues1[2];
        int cTotal1 = cpuValues1[3] + cBusy1;

        char * fileText2Split = strtok(fileText2, " ");
        fileText2Split = strtok(NULL, " ");
        int cpuValues2[4];
        k = 0;
        for (k = 0; k < 4; k++) {
            cpuValues2[k] = atoi(fileText2Split);
            fileText2Split = strtok(NULL, " ");
        }

        int cBusy2 = cpuValues2[0] + cpuValues2[1] + cpuValues2[2];
        int cTotal2 = cpuValues2[3] + cBusy2;

        int tempH = cBusy2 - cBusy1;
        int tempL = cTotal2 - cTotal1;

        float util = (float)tempH / (float)tempL;
        float power = 0;

        if (util > 0.5) {
            power = 1.4584 * util + 4.7788;
        } else {
            power = 3.4495 * util + 3.8563;
        }

        printf("Power - %f W\nUtilisation - %f %%\n\n", power, util);
    }

    return 0;
}
