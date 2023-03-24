#! /bin/bash
rm -r build
mkdir build
cd build
export PICO_SDK_PATH=/home/pi/Documents/gdp/pico-benchmarking-files/pico-sdk
cmake .. -DWIFI_SSID=SOTON-IoT -DWIFI_PASSWORD=iHb53kKlQcSj ..
cmake --build .
sudo openocd -f interface/picoprobe.cfg -f target/rp2040.cfg -c "program cycles_benchmark_client.elf verify reset exit"
