#! /bin/bash
rm -r build
mkdir build
cd build
export PICO_SDK_PATH=/home/pi58/pico-dilithium/pico-sdk
cmake .. -DWIFI_SSID=wifi_name -DWIFI_PASSWORD=password ..
cmake --build .
sudo openocd -f interface/picoprobe.cfg -f target/rp2040.cfg -c "program pico_w_dilithium_client.elf verify reset exit"