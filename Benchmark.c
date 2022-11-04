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
#include "client-pq-tls13.h"

/* application args */
char *server_addr = "127.0.0.1";
char *cert_file_path = "./certs/ca-ecc-cert.pem";
int kem[] = {WOLFSSL_ECC_SECP256R1, WOLFSSL_KYBER_LEVEL5, WOLFSSL_SABER_LEVEL5};
char *kemNames[3] = {"ECDSA", "Kyber", "Saber"};
char * MsgToServer = "";

int benchmark_KEM() {
  /* run client 5 times */
  int i;
  for (i = 0; i < 3; i++) {
    printf("Benchmarked Handshake using %s\n", kemNames[i]);
    run_client(server_addr, cert_file_path, kem[i], "Test");
    printf("\n");
  }

  return 0;
}

int benchmark_DS() {
  return 0;
}

int main() {

  benchmark_KEM(); 

  run_client(server_addr, cert_file_path, kem[0], "shutdown");

  return 0;
}