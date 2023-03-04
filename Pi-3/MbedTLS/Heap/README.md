# PQC Heap Memory Usage Benchmarking on the Raspberry Pi 3b+

Instructions:


## Full Test
This tests all combinations of algorithms

### Client

1. Set the environment variable `MBEDTLS_PATH` to the path of your mbedtls library
2. Modify `../ssl_client1.c` to ensure `GDP_MEM_TEST` is defined (line 94)
3. Run `test_client.sh` from `/GDP-PQC/Pi-3/MbedTLS/Heap`

### Server
1. Set the environment variable `MBEDTLS_PATH` to the path of your mbedtls library
2. Modify `../ssl_server.c` to ensure `GDP_MEM_TEST` is defined (line 111)
2. Run `test_server.sh` from `/GDP-PQC/Pi-3/MbedTLS/Heap`

## Partial Test
This tests all algorithms but only for the security levels specified in the mbedtls pqc configuration files. For more information on how to modify these security levels see the readme of the parent directory.

### Client

1. From `/GDP-PQC/Pi-3/MbedTLS/Heap`, compile client.c using the following command

    `gcc client.c ../ssl_client1.c -lmbedtls -lmbedx509 -lmbedcrypto -lm -o client`

2. Run the client using `./client` or to save the results to a file use 
     
    `./client |& tee ./results.txt`