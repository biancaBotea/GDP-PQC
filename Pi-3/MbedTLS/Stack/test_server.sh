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

		echo "Dilithium L$k" |& tee -a ./results.txt
		gcc server.c ../ssl_server.c -lmbedtls -lmbedx509 -lmbedcrypto -lm -o server
    	valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./server 6
		process_results
    	valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./server 7
		process_results
    	valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./server 8
		process_results
	done
	echo "Sphincs" |& tee -a ./results.txt
	valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./server 4
	process_results
	valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./server 5
	process_results
	echo "ECDSA" |& tee -a ./results.txt
	valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./server 1
	process_results
	valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./server 2
	process_results
done
echo "ECDHE - Sphincs" |& tee -a ./results.txt
valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./server 3
process_results
echo "ECDHE - Sphincs" |& tee -a ./results.txt
valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./server 0
process_results