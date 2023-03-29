#! /bin/bash
WRK_DIR="`pwd`"

debug=1
test_name="Power"

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