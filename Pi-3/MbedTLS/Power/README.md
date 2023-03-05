# PQC Power Consumption Benchmarking on the Raspberry Pi 3b+

Instructions:

(Note: GDP_MEM_TEST should not be defined for these tests)

## Full Test
This tests all combinations of algorithms

### Client

1. Set the environment variable `MBEDTLS_PATH` to the path of your mbedtls library
2. Set `server_addr` (client.c, line: 52) to the IP address of the server
3. Set `test_length` (client.c, line: 53) to the desired test duration in seconds
4. Run `test_client.sh` from `/GDP-PQC/Pi-3/MbedTLS/Power`

### Server
1. Set the environment variable `MBEDTLS_PATH` to the path of your mbedtls library
2. Run `test_server.sh` from `/GDP-PQC/Pi-3/MbedTLS/Power`

## Partial Test
This tests all algorithms but only for the security levels specified in the mbedtls pqc configuration files. For more information on how to modify these security levels see the readme of the parent directory.

### Client

1. Set `server_addr` (client.c, line: 52) to the IP address of the server
2. Set `test_length` (client.c, line: 53) to the desired test duration in seconds
3. From `/GDP-PQC/Pi-3/MbedTLS/Power`, compile client.c using the following command

    `gcc client.c ../ssl_client1.c -lmbedtls -lmbedx509 -lmbedcrypto -lm -o client`

4. Run the client using `./client` or to save the results to a file use 
     
    `./client |& tee ./results.txt`

### Server

1. From `/GDP-PQC/Pi-3/MbedTLS/Power`, compile client.c using the following command

    `gcc server.c ../ssl_server.c -lmbedtls -lmbedx509 -lmbedcrypto -lm -o server`

2. Run the client using `./server` or to save the results to a file use 
     
    `./server |& tee ./results.txt`