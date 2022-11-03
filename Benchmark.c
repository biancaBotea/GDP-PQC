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

/* extra src files */
#include "client-pq-tls13.h"

int main() {
  /* application args */
  char *server_addr = "10.42.0.211";
  char *cert_file_path = "./certs/falcon_level1_root_cert.pem";

  /* run client 5 times */
  int i;
  for (i = 0; i < 5; i++) {
    run_client(server_addr, cert_file_path);
  }

  return 0;
}