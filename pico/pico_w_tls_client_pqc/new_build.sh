#!/bin/bash
echo "Rebuilding program"
rm -r build
mkdir build
cd build
export PICO_SDK_PATH=/home/pi57/pico-experimental/pico-sdk
cmake .. -DWIFI_SSID=SOTON-IoT -DWIFI_PASSWORD=iHb53kKlQcSj ..
make -j4
if test "$1" = "-noflash"; then
	exit
fi
sudo openocd -f interface/picoprobe.cfg -f target/rp2040.cfg -c "program pico_w_tls_client_pqc.elf verify reset exit"
