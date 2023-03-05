#!/bin/bash

WRK_DIR="`pwd`"

cd $WRK_DIR

for j in 1 3 5
do
	echo "Kyber & Saber l$j" |& tee -a ./results.txt
	for k in 2 3 5
	do
		ccp ../test_config/kyber_params_l$j.h $MBEDTLS_PATH/include/pq/kyber_params.h
		cp ../test_config/saber_params_l$j.h $MBEDTLS_PATH/include/pq/saber_params.h
		cp ../test_config/dilithium_params_l$k.h $MBEDTLS_PATH/include/pq/dilithium_params.h
		cp ../test_config/new_certs_l$k.h ../new_certs.h

		cd $MBEDTLS_PATH
		rm -rf build
		mkdir build
		cd build
		cmake .. -DENABLE_TESTING=OFF ..
		cmake --build .
		sudo cmake --install .

		cd $WRK_DIR

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