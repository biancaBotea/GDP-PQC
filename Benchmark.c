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
#include <time.h>

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


// Benchmarks KEM only with ECDSA signature scheme (Deprecated)
int benchmark_KEM() {
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


// Benchmarks DS only with ECC key exchange (Deprecated)
int benchmark_DS() {
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
  

  // Test all KEMs for all DSs
  int i;
  int j;
  for (i = 0; i < 3; i++) {
    for (j = 0; j < 3; j++) {
      printf("\nDS: %s \t KEM: %s\n", sigSchemeNames[i], kemNames[j]);
      sleep(3);

      // Measure cpu stats for power calculation pre handshake
      FILE *fileStream; 
      char fileText1 [100];
      fileStream = fopen ("/proc/stat", "r"); 
      fgets (fileText1, 100, fileStream); 
      fclose(fileStream);

      // Calculate the time taken by run_client()
      clock_t t;
      t = clock();
      run_client(server_addr, cert_file_paths[i], kem[j], "shutdown");
      t = clock() - t;
      double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds

      // Measure and process cpu stats for power calculations post handshake
      char fileText2 [100];
      fileStream = fopen ("/proc/stat", "r"); 
      fgets (fileText2, 100, fileStream); 
      fclose(fileStream);

      printf("%s%s", fileText1, fileText2);

      char * fileText1Split = strtok(fileText1, " ");
      fileText1Split = strtok(NULL, " ");
      int cpuValues1[4];
      int k;
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

      printf("tempH = %d\ttempL = %d\ttime=%f\n", tempH, tempL, time_taken);
    }
  }

  return 0;
}