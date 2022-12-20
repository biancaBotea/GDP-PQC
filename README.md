# GDP-PQC

We are going to modify existing benchmarking software to easily analyse and compare the security,
implementation costs and energy consumption of PQC methods.

## Getting started with the raspberry pi

For the raspberrt pi part of this project we need to install, liboqs, wolfssl, openssl, ops and wolfssl-example

Befor we start installing everithing make sure the pi is up to date and you have git and cmake installed.

We start with liboqs:

	mkdir ~/oqs && cd ~/oqs
    git clone --single-branch https://github.com/open-quantum-safe/liboqs.git
    cd liboqs/
    git checkout af76ca3b1f2fbc1f4f0967595f3bb07692fb3d82
    mkdir build && cd build
    cmake -DOQS_USE_OPENSSL=0 ..
    make all && sudo make install

Now for the wolfssl we first need to download it from https://www.wolfssl.com/download/.

	cd ~/oqs/wolfssl
    ./configure --with-liboqs --with-arm-target=cortex --enable-trackmemory --enable-stacksize
    make all && sudo make install && sudo ldconfig
    
   
Now we need to clone the osp repo for the signature schemes:

	git clone https://github.com/wolfSSL/osp.git
    
    
Now we have to install the openssl patch:

	cd ~/oqs/
	git clone --single-branch --branch=OQS-OpenSSL_1_1_1-stable https://github.com/open-quantum-safe/openssl.git
	cd openssl
	git checkout e9160975eeb9796ff3550e8c2c35db63157a409b
	patch -p1 < /path/to/osp/oqs/openssl-sphincs.patch
	./config no-shared && make all
	
	To make the certificates you need to run:
	
To test wolfssl you need to install wolfssl-example:

	cd ~/oqs
	git clone https://github.com/wolfSSL/wolfssl-examples.git
	cd ~/oqs/wolfssl-examples/pq
	./server-pq-tls13
	
And on differnet terminal run:
	./client-pq-tls13 ip.address

## Setting up the pi pico w

To use wolfssl on the pico W from the pi we can running the setup scrip to installation
most of the steps in this Getting Started guide

	 wget https://raw.githubusercontent.com/raspberrypi/pico-setup/master/pico_setup.sh
	 chmod +x pico_setup.sh
	 ./pico_setup.sh 
	 sudo reboot

To install the toolchain run:

	sudo apt install cmake gcc-arm-none-eabi libnewlib-arm-none-eabi libstdc++-arm-none-eabi-newlib build-essential 

Now we need to install and build the SDK fot the pico W:

	 cd ~/pico/pico-examples/build
	 export PICO_SDK_PATH=../../pico-sdk
	 cmake .. -DPICO_BOARD=pico_w -DWIFI_SSID="Your Network" -DWIFI_PASSWORD="Your Password" ..
	 
Now turn ssh on by going into raspberry pi configuration

Because liboqs is not suported on the cortex M0 we are going to use mbed TLS which is implemented in the pico-sdk develope branch so we need to switch to it:
	cd ~/pico/pico-sdk
	git switch develop
	git submodule update --init

This mbed only has the classic algorithms so to use the PQC ones we need to :

	git clone https://github.com/kbuersti/mbedtls.git
	cd mbedtls
	git switch mbedtls-2.16-pqc
	git submodule update --init
	mkdir build && cd build
	cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On ../
	cmake --build .
<!-- 
*****DON'T DO THIS YET AS IT BREAKS THINGS UP*****

Before we start building this we have to install doxygen:

	cd && git clone https://github.com/doxygen/doxygen.git
	cd doxygen
	mkdir build && cd build
	sudo apt-get instatall bison
	sudo apt-get instatall flux
	sudo apt-get instatall libclang1-9
	cmake -G "Unix Makefiles" ..
	make && sudo make install

***More to be added**** -->

Use this to run the programm over SWD
	
	openocd -f interface/raspberrypi-swd.cfg -f target/rp2040.cfg -c "program blink/blink.elf verify reset exit"

To see the results of the code you need to open the serial port:

	sudo apt install minicom
	minicom -b 115200 -o -D /dev/serial0

To run ur project you have to write a CMakeLists.txt file then :

	cp ../pico-sdk/external/pico_sdk_import.cmake .
	cp ../pico-examples/pico_w/lwipopts_examples_common.h lwipopts.h
	cd build
	export PICO_SDK_PATH=../../pico-sdk
	cmake -DPICO_BOARD=pico_w -DWIFI_SSID="Your Network" -DWIFI_PASSWORD="Your Password" ..
	make

## Build

Compile Benchmark.c using:

    gcc Benchmark.c client-pq-tls13.c -lwolfssl -o Benchmark

Then run Benchmark executable as normal.
