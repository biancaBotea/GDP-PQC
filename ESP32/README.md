# ESP32
We are using the ESP32-S3-DevKitC-1.

We are going to use VSCode as our IDE with the espressif ESP-IDF extancion. 

 ## Prerequisits (for mac and linux)
 - cmake 
 - ninja 
 - dfu-util
 - ccache
 - python 3
 - Visual Studio Code

 A step by step installation for mac and linus can be found [here](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/get-started/linux-macos-setup.html#:~:text=your%20ESP32%2DS3.-,Step%201.%20Install%20Prerequisites,-Step%202.%20Get) but don't go further then step 1 as we are going to install the ESP-IDF though the VSCode IDE.

 ## Installing ESP-IDF

 This [video](https://www.youtube.com/watch?v=Lc6ausiKvQM&list=TLPQMjYxMTIwMjLsECCqAIaFWA&index=3&ab_channel=EspressifSystems) walks you thruogh this process. Some things to note before wathcing the video is that the target we are using is the esp32s3 chip (via ESP_PROG) 
 
 ![Screen Shot 2022-11-26 at 3 45 16 PM](https://user-images.githubusercontent.com/108932109/204097527-02a3a8d9-375f-49ae-9a8e-7dfb5b483577.png)
 
And the flasing method is UART, so you need to make sure the microcomtoller is connected to your computer through the UART port.

At the end your status bar shoudl look like this:

![Screen Shot 2022-11-26 at 3 58 05 PM](https://user-images.githubusercontent.com/108932109/204097631-a309c18c-75f4-4b8d-858c-0914555eee70.png)

If u got through the blink example the provide you might have to change line 22 from main to
```
 #define BLINK_GPIO 38 
```
as that is the LED pot for this specific device.




