#!/bin/bash

WRK_DIR="`pwd`"

flash_pico () {
	cd $WRK_DIR/Benchmarks/Latency
	sudo rm -r build
	mkdir build
	cd build
	cmake .. -DWIFI_SSID="TOMS LAPTOP" -DWIFI_PASSWORD="12345678" ..
	cmake --build --config Release .
	sudo openocd -f interface/picoprobe.cfg -f target/rp2040.cfg -c "program latency_benchmark_client.elf verify reset exit"
}

rm results.txt
rm results_srv.txt

for j in 1 3 5
do
	echo "Kyber & Saber l$j"
	for k in 2 3 5
	do
		cd $WRK_DIR		
		cp ./config/kyber_params_l$j.h $PICO_SDK_PATH/lib/mbedtls/include/pq/kyber_params.h
		cp ./config/saber_params_l$j.h $PICO_SDK_PATH/lib/mbedtls/include/pq/saber_params.h
		cp ./config/dilithium_params_l$k.h $PICO_SDK_PATH/lib/mbedtls/include/pq/dilithium_params.h
		cp ./config/new_certs_l$k.h $WRK_DIR/Benchmarks/new_certs.h

		# Give Server time to compile mbed
		sleep 30
		
		echo "Dilithium l$k"
		# Flash pico once with dilithium client then run it another 2 times by resetting device with breaks in between to allow for server to restart/recompile?
		cd $WRK_DIR
		cp ./config/dilithium_client.c $WRK_DIR/Benchmarks/Latency/client.c
		flash_pico
		cd $WRK_DIR
		sudo python3 dmm_control.py -l on -f k${j}d${k}t1.csv
		python3 ./termination_server.py
		sudo python3 dmm_control.py -l off

		sudo openocd -f interface/picoprobe.cfg -f target/rp2040.cfg -c "init; reset; exit"
		sudo python3 dmm_control.py -l on -f k${j}d${k}t2.csv
		python3 ./termination_server.py
		sudo python3 dmm_control.py -l off

		sudo openocd -f interface/picoprobe.cfg -f target/rp2040.cfg -c "init; reset; exit"
		sudo python3 dmm_control.py -l on -f k${j}d${k}t3.csv
		python3 ./termination_server.py
		sudo python3 dmm_control.py -l off
	done

	echo "Sphincs"
	cd $WRK_DIR
	cp ./config/sphincs_client.c $WRK_DIR/Benchmarks/Latency/client.c
	flash_pico
	sudo python3 dmm_control.py -l on -f k${j}d${k}t4.csv
	cd $WRK_DIR
	python3 ./termination_server.py
	sudo python3 dmm_control.py -l off

	sudo openocd -f interface/picoprobe.cfg -f target/rp2040.cfg -c "init; reset; exit"
	sudo python3 dmm_control.py -l on -f k${j}d${k}t5.csv
	python3 ./termination_server.py
	sudo python3 dmm_control.py -l off

	echo "ECDSA"
	cd $WRK_DIR
	cp ./config/ecdsa_client.c $WRK_DIR/Benchmarks/Latency/client.c
	flash_pico
	sudo python3 dmm_control.py -l on -f k${j}d${k}t6.csv
	cd $WRK_DIR
	python3 ./termination_server.py
	sudo python3 dmm_control.py -l off

	sudo openocd -f interface/picoprobe.cfg -f target/rp2040.cfg -c "init; reset; exit"
	sudo python3 dmm_control.py -l on -f k${j}d${k}t7.csv
	python3 ./termination_server.py
	sudo python3 dmm_control.py -l off
	
done

echo "ECDHE with Sphincs or ECDSA"
cd $WRK_DIR
cp ./config/sphincs_client.c $WRK_DIR/Benchmarks/Latency/client.c
flash_pico
sudo python3 dmm_control.py -l on -f k${j}d${k}t8.csv
cd $WRK_DIR
python3 ./termination_server.py
sudo python3 dmm_control.py -l off

cd $WRK_DIR
cp ./config/ecdsa_client.c $WRK_DIR/Benchmarks/Latency/client.c
flash_pico
sudo python3 dmm_control.py -l on -f k${j}d${k}t9.csv
cd $WRK_DIR
python3 ./termination_server.py
sudo python3 dmm_control.py -l off
