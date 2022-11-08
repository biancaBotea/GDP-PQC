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

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* extra src files */
#include "client-pq-tls13.h"

/* application args */
char *server_addr = "127.0.0.1";
char *cert_file_paths[] = {"./certs/ca-ecc-cert.pem", "./certs/falcon_level5_root_cert.pem", "./certs/dilithium_level5_root_cert.pem"};
char *sigSchemeNames[3] = {"ECDSA", "Falcon", "Dilithium"};
int kem[] = {WOLFSSL_ECC_SECP256R1, WOLFSSL_KYBER_LEVEL5, WOLFSSL_SABER_LEVEL5};
char *kemNames[3] = {"ECDHE", "Kyber", "Saber"};
char * MsgToServer = "";

// Benchmarks KEM only with ECDSA signature scheme
int benchmark_KEM() {
  /* run KEM tests */
  printf("Started KEM Benchmarking\n");

  int i;
  for (i = 0; i < 3; i++) {
    printf("Benchmarking Handshake using %s\n", kemNames[i]);
    run_client(server_addr, cert_file_paths[0], kem[i], "Test");
    printf("\n");
  }

  run_client(server_addr, cert_file_paths[0], kem[0], "shutdown");

  printf("Finished KEM Benchmarking\n\n");

  return 0;
}

// Benchmarks DS only with ECC key exchange
int benchmark_DS() {
  /* run signature tests */
  printf("Started Signature Benchmarking\n");

  int i;
  for (i = 0; i < 3; i++) {
    sleep(3);
    printf("\nBenchmarking Handshake using %s\n", sigSchemeNames[i]);
    run_client(server_addr, cert_file_paths[i], kem[0], "Test");
    sleep(3);
    run_client(server_addr, cert_file_paths[i], kem[0], "shutdown");
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
      sleep(3);
      run_client(server_addr, cert_file_paths[i], kem[j], "shutdown");
    }
  }

  return 0;
}