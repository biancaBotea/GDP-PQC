#!/bin/bash

WRK_DIR="`pwd`"

run_test () {
	let "count++"
	if [ $start -le $count ]
	then
		echo "Initialising Logging"
		python3 messenger.py -c Start
		sleep 5
		echo "Starting test"
		./server $1
		echo "Terminating Logging"
		python3 messenger.py -c Stop
		sleep 5
		echo "Test Finished"
		echo ""
	fi
} 

cd $WRK_DIR

for j in 1 3 5
do
	echo "Kyber & Saber L$j ---------"
	for k in 2 3 5
	do
		if [ $start -le $count ]
		then
			echo "Dilithium L$k -------------"
			echo "Copying Files"
			cp ../test_config/kyber_params_l$j.h $MBEDTLS_PATH/include/pq/kyber_params.h
			cp ../test_config/saber_params_l$j.h $MBEDTLS_PATH/include/pq/saber_params.h
			cp ../test_config/dilithium_params_l$k.h $MBEDTLS_PATH/include/pq/dilithium_params.h
			cp ../test_config/new_certs_l$k.h ../new_certs.h

			cd $MBEDTLS_PATH
			rm -rf build
			mkdir build
			cd build
			echo "Building Mbed TLS"
			cmake .. -DENABLE_TESTING=OFF .. &> /dev/null
			cmake --build . &> /dev/null
			echo "Installing Mbed TLS"
			sudo cmake --install . &> /dev/null

			cd $WRK_DIR

			echo "Compiling server application"
			gcc server.c ../ssl_server.c -lmbedtls -lmbedx509 -lmbedcrypto -lm -o server
		fi
		
		run_test 6
		run_test 7
		run_test 8
	done

	echo "Sphincs -------------------"
	run_test 3
	run_test 4
	run_test 5
	echo "ECDSA ---------------------"
	run_test 1
	run_test 2
done

run_test 0