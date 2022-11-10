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

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* extra src files */
#include "server-pq-tls13.h"

/* application args */
char *cert_file_paths[] = {"./certs/server-ecc.pem", "./certs/falcon_level5_entity_cert.pem", "./certs/dilithium_level5_entity_cert.pem"};
char *key_file_paths[] = {"./certs/ecc-key.pem", "./certs/falcon_level5_entity_key.pem", "./certs/dilithium_level5_entity_key.pem"};
char *sigSchemeNames[3] = {"ECDSA", "Falcon", "Dilithium"};
int kem[] = {WOLFSSL_ECC_SECP256R1, WOLFSSL_KYBER_LEVEL5, WOLFSSL_SABER_LEVEL5};
char *kemNames[3] = {"ECDHE", "Kyber", "Saber"};
char * MsgToServer = "";
extern int *mShutdownPtr;

int benchmark_KEM() {
  /* run KEM tests */
  printf("Started KEM Benchmarking\n");

  run_server(cert_file_paths[0], key_file_paths[0]);

  printf("Finished KEM Benchmarking\n\n");
  return 0;
}

int benchmark_DS() {
  /* run signature tests */
  printf("Started Signature Benchmarking\n");

  int i;
  for (i = 0; i < 3; i++) {
    *mShutdownPtr = 0; //Reset shutdown control boolean for server
    run_server(cert_file_paths[i], key_file_paths[i]);
    sleep(1); //Server must wait for port to be released by OS
  }

  printf("Finished Signature Benchmarking\n\n");

  return 0;
}

int main() {

  int i;
  int j;
  for (i = 0; i < 3; i++) {
    for (j = 0; j < 3; j++) {
      printf("\nDS: %s \t KEM: %s\n", sigSchemeNames[i], kemNames[j]);
      *mShutdownPtr = 0; //Reset shutdown control boolean for server
      run_server(cert_file_paths[i], key_file_paths[i]);
      sleep(1); //Server must wait for port to be released by OS
    }
  }

  return 0;
}