#!/bin/bash

certs=("../../../Certs/ca-ecc-cert.pem"
       "../../../Certs/falcon_level1_root_cert.pem"
       "../../../Certs/falcon_level5_root_cert.pem"
       "../../../Certs/dilithium_level2_root_cert.pem"
       "../../../Certs/dilithium_level3_root_cert.pem"
       "../../../Certs/dilithium_level5_root_cert.pem")
keys=("../../../Certs/ecc-key.pem"
      "../../../Certs/falcon_level1_root_key.pem"
      "../../../Certs/falcon_level5_root_key.pem"
      "../../../Certs/dilithium_level2_root_key.pem"
      "../../../Certs/dilithium_level3_root_key.pem"
      "../../../Certs/dilithium_level5_root_key.pem")
kem=(WOLFSSL_ECC_SECP256R1
     WOLFSSL_KYBER_LEVEL1
     WOLFSSL_KYBER_LEVEL3
     WOLFSSL_KYBER_LEVEL5
     WOLFSSL_SABER_LEVEL1
     WOLFSSL_SABER_LEVEL3
     WOLFSSL_SABER_LEVEL5)

for i in {0..5}
do 
    for j in {0..6}
    do
        sleep 1
        /home/ubuntu/Documents/GDP/wolfssl/examples/server/server -v 4 --pqc=${kem[$j]} -c ${certs[$i]} -k ${keys[$i]}
    done
done
