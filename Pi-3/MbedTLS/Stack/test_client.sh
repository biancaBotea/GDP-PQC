#!/bin/bash

WRK_DIR="`pwd`"
debug=0

process_results () {
	bash get_results.sh |& tee -a ./results.txt
	rm massif*
}

cd $WRK_DIR

for j in 1 3 5
do
	echo "Kyber & Saber L$j" |& tee -a ./results.txt
	for k in 2 3 5
	do
		sleep 5
		cp ../test_config/kyber_params_l$j.h $MBEDTLS_PATH/include/pq/kyber_params.h
		cp ../test_config/saber_params_l$j.h $MBEDTLS_PATH/include/pq/saber_params.h
		cp ../test_config/dilithium_params_l$k.h $MBEDTLS_PATH/include/pq/dilithium_params.h
		cp ../test_config/new_certs_l$k.h ../new_certs.h

		cd $MBEDTLS_PATH
		sudo rm -rf build
		mkdir build
		cd build
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

		echo "Dilithium L$k" |& tee -a ./results.txt
		gcc client.c ../ssl_client1.c -lmbedtls -lmbedx509 -lmbedcrypto -lm -o client
    	valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./client 6
		process_results
		sleep 2
    	valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./client 7
		process_results
		sleep 2
    	valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./client 8
		process_results
	done
	echo "Sphincs" |& tee -a ./results.txt
	valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./client 4
	process_results
	sleep 2
	valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./client 5
	process_results
	sleep 2
	echo "ECDSA" |& tee -a ./results.txt
	valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./client 1
	process_results
	sleep 2
	valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./client 2
	process_results
done
echo "ECDHE - Sphincs" |& tee -a ./results.txt
valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./client 3
process_results
sleep 2
echo "ECDHE - Sphincs" |& tee -a ./results.txt
valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./client 0
process_results