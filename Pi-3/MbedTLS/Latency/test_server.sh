#!/bin/bash

cd /home/pi58/BenchmarkPi3/Latency
rm results.txt

for j in 1 3 5
do
	echo "Kyber & Saber l$j" |& tee -a ./results.txt
	for k in 2 3 5
	do
		cp ./config/kyber_params_l$j.h /home/pi58/mbedtls/include/pq/kyber_params.h
		cp ./config/saber_params_l$j.h /home/pi58/mbedtls/include/pq/saber_params.h
		cp ./config/dilithium_params_l$k.h /home/pi58/mbedtls/include/pq/dilithium_params.h
		cp ./config/new_certs_l$k.h ../new_certs.h

		cd /home/pi58/mbedtls
		rm -rf build
		mkdir build
		cd build
		cmake .. -DENABLE_TESTING=OFF ..
		cmake --build .
		cmake --install .

		cd /home/pi58/BenchmarkPi3/Latency

		gcc server.c ../ssl_server.c -lmbedtls -lmbedx509 -lmbedcrypto -lm -o server
		echo "Dilithium l$k" |& tee -a ./results.txt
		./server 6 |& tee -a ./results.txt
		./server 7 |& tee -a ./results.txt
		./server 8 |& tee -a ./results.txt
	done
	echo "Sphincs" |& tee -a ./results.txt
	./server 3 |& tee -a ./results.txt
	./server 4 |& tee -a ./results.txt
	./server 5 |& tee -a ./results.txt
	echo "ECDSA" |& tee -a ./results.txt
	./server 1 |& tee -a ./results.txt
	./server 2 |& tee -a ./results.txt
done

echo "ECDSA & ECDHE" |& tee -a ./results.txt
./server 0 |& tee -a ./results.txt