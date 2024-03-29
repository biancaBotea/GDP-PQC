#!/bin/bash

WRK_DIR="`pwd`"
debug=0

cd $WRK_DIR

for j in 1 3 5
do
	echo "Kyber & Saber l$j" |& tee -a ./results.txt
	for k in 2 3 5
	do
		sleep 5
		echo "Copying Files"
		cp ../test_config/kyber_params_l$j.h $MBEDTLS_PATH/include/pq/kyber_params.h
		cp ../test_config/saber_params_l$j.h $MBEDTLS_PATH/include/pq/saber_params.h
		cp ../test_config/dilithium_params_l$k.h $MBEDTLS_PATH/include/pq/dilithium_params.h
		cp ../test_config/new_certs_l$k.h ../new_certs.h

		echo "Building mbedtls"
		cd $MBEDTLS_PATH
		rm -rf build
		mkdir build
		cd build
		if [ $debug -eq 1 ]
		then
			cmake .. -DENABLE_TESTING=OFF ..
			cmake --build .
			sudo cmake --install .
		else
			cmake .. -DENABLE_TESTING=OFF .. &> /dev/null
			cmake --build . &> /dev/null
			sudo cmake --install . &> /dev/null
		fi

		cd $WRK_DIR

		echo "Building client application"
		gcc client.c ./ssl_client1.c -lmbedtls -lmbedx509 -lmbedcrypto -lm -o client
		echo "Dilithium l$k" |& tee -a ./results.txt
		./client 6 |& tee -a ./results.txt
		./client 7 |& tee -a ./results.txt
		./client 8 |& tee -a ./results.txt
	done
	echo "Sphincs" |& tee -a ./results.txt
	./client 4 |& tee -a ./results.txt
	./client 5 |& tee -a ./results.txt
	echo "ECDSA" |& tee -a ./results.txt
	./client 1 |& tee -a ./results.txt
	./client 2 |& tee -a ./results.txt
done

echo "ECDSA & ECDHE" |& tee -a ./results.txt
./client 3 |& tee -a ./results.txt
./client 0 |& tee -a ./results.txt