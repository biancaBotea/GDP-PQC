#! /bin/bash
cd ./Benchmarks/Latency
sudo rm -r build
mkdir build
cd build
echo "Building pico-sdk and client application"
cmake .. -DWIFI_SSID="TOMS LAPTOP" -DWIFI_PASSWORD="12345678" .. #&> /dev/null
cmake --build . --config Release #&> /dev/null
echo "Flashing Pico"
sudo openocd -f interface/picoprobe.cfg -f target/rp2040.cfg -c "program latency_benchmark_client.elf verify reset exit" #&> /dev/null
