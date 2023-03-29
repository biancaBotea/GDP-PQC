#!/bin/bash

WRK_DIR="`pwd`"

debug=1

flash_pico () {
	cd $WRK_DIR/Benchmarks/Latency
	sudo rm -r build
	mkdir build
	cd build
	echo "Building pico-sdk and client application"
	if [ $debug -eq 1 ]
	then
		cmake .. -DWIFI_SSID="TOMS LAPTOP" -DWIFI_PASSWORD="12345678" ..
		cmake --build . --config Release 
		echo "Flashing Pico"
		sudo openocd -f interface/picoprobe.cfg -f target/rp2040.cfg -c "program latency_benchmark_client.elf verify reset exit"
	else
		cmake .. -DWIFI_SSID="TOMS LAPTOP" -DWIFI_PASSWORD="12345678" .. &> /dev/null
		cmake --build . --config Release &> /dev/null
		echo "Flashing Pico"
		sudo openocd -f interface/picoprobe.cfg -f target/rp2040.cfg -c "program latency_benchmark_client.elf verify reset exit" &> /dev/null
	fi
}

reset_pico () {
	echo "Resetting Pico - Starting test"
	if [ $debug -eq 1 ]
	then
		sudo openocd -f interface/picoprobe.cfg -f target/rp2040.cfg -c "init; reset; exit"
	else
		sudo openocd -f interface/picoprobe.cfg -f target/rp2040.cfg -c "init; reset; exit" &> /dev/null
	fi
}

log_test () {
	cd $WRK_DIR
	echo "Initialising Logging"
	sudo python3 dmm_control.py -l on -f k${1}d${2}t1.csv
	python3 ./termination_server.py
	echo "Terminating Logging"
	sudo python3 dmm_control.py -l off
	echo "Test Finished"
	echo ""
}

for j in 5
do
	echo "Kyber & Saber l$j"
	for k in 5
	do
		cd $WRK_DIR
		echo "Copying files"
		cp ./config/kyber_params_l$j.h $PICO_SDK_PATH/lib/mbedtls/include/pq/kyber_params.h
		cp ./config/saber_params_l$j.h $PICO_SDK_PATH/lib/mbedtls/include/pq/saber_params.h
		cp ./config/dilithium_params_l$k.h $PICO_SDK_PATH/lib/mbedtls/include/pq/dilithium_params.h
		cp ./config/new_certs_l$k.h $WRK_DIR/Benchmarks/new_certs.h

		# Give Server time to compile mbed
		echo "Waiting for server to compile Mbed TLS"
		sleep 28
		
		echo "Dilithium l$k"
		# Flash pico once with dilithium client then run it another 2 times by resetting device with breaks in between to allow for server to restart/recompile?
		cd $WRK_DIR
		cp ./config/dilithium_client.c $WRK_DIR/Benchmarks/Latency/client.c
		
		flash_pico
		log_test $j $k

		reset_pico
		log_test $j $k

		reset_pico
		log_test $j $k
	done

	echo "Sphincs"
	cd $WRK_DIR
	cp ./config/sphincs_client.c $WRK_DIR/Benchmarks/Latency/client.c
	
	flash_pico
	log_test $j $k

	reset_pico
	log_test $j $k

	echo "ECDSA"
	cd $WRK_DIR
	cp ./config/ecdsa_client.c $WRK_DIR/Benchmarks/Latency/client.c
	
	flash_pico
	log_test $j $k

	reset_pico
	log_test $j $k
	
done

echo "ECDHE with Sphincs or ECDSA"
cd $WRK_DIR
cp ./config/sphincs_client.c $WRK_DIR/Benchmarks/Latency/client.c

flash_pico
log_test $j $k

cd $WRK_DIR
cp ./config/ecdsa_client.c $WRK_DIR/Benchmarks/Latency/client.c

flash_pico
log_test $j $k
