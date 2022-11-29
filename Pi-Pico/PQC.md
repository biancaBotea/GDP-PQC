Run pqc code.
Clone pico-sdk from the develop branch:
	
	git clone -b develop https://github.com/raspberrypi/pico-sdk.git

Then clone the pqc library of mbedtls:

	git clone -b mbedtls-2.16-pqc https://github.com/kbuersti/mbedtls.git
	
Replace the mbedtls folder in pico-sdk/lib with the new one that was cloned.

Now, edit the CMakeLists.txt in the library folder
to include all the files in that folder.
Go to pico-sdk/src/rp2_common/pico_mbedtls and replace the CMakeLists.txt
with the one provided.

The client should now be ready to build. Clone the client code and:

	mkdir build
	cd build
	export PICO_SDK_PATH=/path/to/sdk (recommend absolute path)
	cmake .. -DWIFI_SSID=SOTON-IoT -DWIFI_PASSWORD=iHb53kKlQcSj ..
	make
	
Run the ssl_server program in programs/ssl on the host device.
Then, run the pico_w_tls_client_pqc on the the pico:

	sudo openocd -f interface/picoprobe.cfg -f target/rp2040.cfg -c "program pico_w_tls_client_pqc.elf verify reset exit"
	
Serial output in new terminal:

	minicom -b 115200 -o -D /dev/ttyACM0
	

	