#!/bin/bash

cd /home/pi57/GDP-PQC/Pi-3/MbedTLS/Latency/
rm results.txt

for j in 1 3 5
do
	echo "Kyber & Saber l$j" |& tee -a ./results.txt
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

		cd /home/pi57/GDP-PQC/Pi-3/MbedTLS/Latency/

		gcc client.c ../ssl_client1.c -lmbedtls -lmbedx509 -lmbedcrypto -lm -o client
		echo "Dilithium l$k" |& tee -a ./results.txt
		./client 6 |& tee -a ./results.txt
		./client 7 |& tee -a ./results.txt
		./client 8 |& tee -a ./results.txt
	done
	echo "Sphincs" |& tee -a ./results.txt
	./client 3 |& tee -a ./results.txt
	./client 4 |& tee -a ./results.txt
	./client 5 |& tee -a ./results.txt
	echo "ECDSA" |& tee -a ./results.txt
	./client 1 |& tee -a ./results.txt
	./client 2 |& tee -a ./results.txt
done

echo "ECDSA & ECDHE" |& tee -a ./results.txt
./client 0 |& tee -a ./results.txt