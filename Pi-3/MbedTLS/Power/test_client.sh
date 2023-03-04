#!/bin/bash

cd /home/pi57/GDP-PQC/Pi-3/MbedTLS/Power/

for j in 1 3 5
do
	for k in 2 3 5
	do
		sleep 5
		cp ./config/kyber_params_l$j.h /home/pi57/mbedtls/include/pq/kyber_params.h
		cp ./config/saber_params_l$j.h /home/pi57/mbedtls/include/pq/saber_params.h
		cp ./config/dilithium_params_l$k.h /home/pi57/mbedtls/include/pq/dilithium_params.h
		cp ./config/new_certs_l$k.h ../new_certs.h

		cd /home/pi57/mbedtls
		rm -rf build
		mkdir build
		cd build
		cmake .. -DENABLE_TESTING=OFF ..
		cmake --build .
		cmake --install .

		cd /home/pi57/GDP-PQC/Pi-3/MbedTLS/Power/

		gcc client.c ../ssl_client1.c -lmbedtls -lmbedx509 -lmbedcrypto -lm -o client
		./client |& tee ./results/$j$j${k}b.txt
	done
done