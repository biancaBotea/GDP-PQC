#! /bin/bash
WRK_DIR="`pwd`"

debug=1
test_name="Power"

j=1
k=2
cert_alg="dilithium"

echo "Copying files"
cp ./Benchmarks/$test_name/config/kyber_params_l$j.h $PICO_SDK_PATH/lib/mbedtls/include/pq/kyber_params.h
cp ./Benchmarks/$test_name/config/saber_params_l$j.h $PICO_SDK_PATH/lib/mbedtls/include/pq/saber_params.h
cp ./Benchmarks/$test_name/config/dilithium_params_l$k.h $PICO_SDK_PATH/lib/mbedtls/include/pq/dilithium_params.h
cp ./Benchmarks/$test_name/config/new_certs_l$k.h $WRK_DIR/Benchmarks/$test_name/new_certs.h
cp ./Benchmarks/$test_name/config/${cert_alg}_client.c $WRK_DIR/Benchmarks/$test_name/client.c

cd $WRK_DIR/Benchmarks/$test_name
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
echo "Done"