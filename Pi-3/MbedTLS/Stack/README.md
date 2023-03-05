# PQC Power Consumption Benchmarking on the Raspberry Pi 3b+

Instructions:

(Note: GDP_MEM_TEST should not be defined for these tests)
(Note: These tests are dependent on the Massif tool from Valgrind)

## Installing Valgrind
The simplest way to install Valgrind on a Raspberry Pi 3b+ is to use the Snap package manager.

### Installing Snap

```bash
$ sudo apt update
$ sudo apt install snapd
$ sudo reboot
$ sudo snap install core
```

### Installing Valgrind

```bash
$ sudo snap install valgrind --classic
```

## Full Test
This tests all combinations of algorithms

### Client

1. Set the environment variable `MBEDTLS_PATH` to the path of your mbedtls library
2. Set `server_addr` (client.c, line: 52) to the IP address of the server
3. Run `test_client.sh` from `/GDP-PQC/Pi-3/MbedTLS/Stack`

### Server
1. Set the environment variable `MBEDTLS_PATH` to the path of your mbedtls library
2. Run `test_server.sh` from `/GDP-PQC/Pi-3/MbedTLS/Stack`

## Partial Test
This tests a specific combination of algorithms depending on the parameters provided. The following combinations are available:

0. ECDHE - ECDSA
1. KYBER - ECDSA
2. SABER - ECDSA
3. ECDHE - SPHINCS
4. KYBER - SPHINCS
5. SABER - SPHINCS
6. ECDHE - DILITHIUM
7. KYBER - DILITHIUM
8. SABER - DILITHIUM

Finally, the security level of each algorithm can be changed by modifying the mbedtls pqc configuration files. For more information on how to modify these security levels see the readme of the parent directory.

### Client

1. Set `server_addr` (client.c, line: 52) to the IP address of the server
2. From `/GDP-PQC/Pi-3/MbedTLS/Stack`, compile client.c using the following command

    `gcc client.c ../ssl_client1.c -lmbedtls -lmbedx509 -lmbedcrypto -lm -o client`

3. Run the client using
     
    `valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./client $i`

4. Inspect the valgrind output using `ms_print` or run `get_results.sh`

### Server

1. From `/GDP-PQC/Pi-3/MbedTLS/Stack`, compile client.c using the following command

    `gcc server.c ../ssl_server.c -lmbedtls -lmbedx509 -lmbedcrypto -lm -o server`

2. Run the client using
     
    `valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./server $i`