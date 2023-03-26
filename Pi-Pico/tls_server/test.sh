#!/bin/bash

WRK_DIR="`pwd`"

cd $WRK_DIR

for j in 1 3 5
do
	echo "Kyber & Saber L$j"
	for k in 5
	do
		sleep 2
		cp ./test_config/kyber_params_l$j.h $MBEDTLS_PATH/include/pq/kyber_params.h
		cp ./test_config/saber_params_l$j.h $MBEDTLS_PATH/include/pq/saber_params.h
		cp ./test_config/dilithium_params_l$k.h $MBEDTLS_PATH/include/pq/dilithium_params.h
		cp ./test_config/new_certs_l$k.h ./new_certs.h

		cd $MBEDTLS_PATH
		sudo rm -rf build
		mkdir build
		cd build
		cmake .. -DENABLE_TESTING=OFF ..
		cmake --build .
		sudo cmake --install .

		cd $WRK_DIR

		echo "Dilithium L$k"
		gcc server.c ./ssl_server.c -lmbedtls -lmbedx509 -lmbedcrypto -lm -o server
		./server 6
		python3 ./termination_client.py

		sleep 2
		./server 7
		python3 ./termination_client.py
		
		sleep 2
		./server 8
		python3 ./termination_client.py
	done
	
	echo "Sphincs"
	sleep 2
	./server 4
	python3 ./termination_client.py
	
	sleep 2
	./server 5
	python3 ./termination_client.py
	
	echo "ECDSA"
	sleep 2
	./server 1
	python3 ./termination_client.py
	
	sleep 2
	./server 2
	python3 ./termination_client.py
done

echo "ECDHE"
sleep 2
./server 3
python3 ./termination_client.py

sleep 2
./server 0
python3 ./termination_client.py