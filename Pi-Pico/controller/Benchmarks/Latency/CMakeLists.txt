cmake_minimum_required(VERSION 3.13)

include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

project(heap_benchmark_client LANGUAGES C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

set(PICO_BOARD pico_w)
#set(WIFI_SSID SOTON-IoT)
#set(WIFI_PASSWORD iHb53kKlQcSj)
set(WIFI_SSID "TOMS LAPTOP")
set(WIFI_PASSWORD "12345678")
set(PICO_MBEDTLS_PATH $ENV{PICO_SDK_PATH}/lib/mbedtls)

pico_sdk_init()

add_subdirectory(src)

add_executable(latency_benchmark_client
        client.c
        ../pico_client.c
        )
target_compile_definitions(latency_benchmark_client PRIVATE
        WIFI_SSID=\"${WIFI_SSID}\"
        WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
        )
target_include_directories(latency_benchmark_client PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/.. # for our common lwipopts
        )
target_link_libraries(latency_benchmark_client
        pico_cyw43_arch_lwip_threadsafe_background
        pico_lwip_mbedtls
        pico_mbedtls
        pico_stdlib
        pico_time
        pqc_utimer
        pqc_systick
        )
pico_add_extra_outputs(latency_benchmark_client)

pico_enable_stdio_usb(latency_benchmark_client 0)
pico_enable_stdio_uart(latency_benchmark_client 1)
