cmake_minimum_required(VERSION 3.13)

include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

project(heap_benchmark_client LANGUAGES C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

set(PICO_BOARD pico_w)
set(WIFI_SSID BTHub6-5FK7)
set(WIFI_PASSWORD DefyAdvanced2!)
set(PICO_MBEDTLS_PATH $ENV{PICO_SDK_PATH}/lib/mbedtls)

pico_sdk_init()

add_executable(heap_benchmark_client
        client.c
        ../pico_client.c
        )
target_compile_definitions(heap_benchmark_client PRIVATE
        WIFI_SSID=\"${WIFI_SSID}\"
        WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
        )
target_include_directories(heap_benchmark_client PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/.. # for our common lwipopts
        )
target_link_libraries(heap_benchmark_client
        pico_cyw43_arch_lwip_threadsafe_background
        pico_lwip_mbedtls
        pico_mbedtls
        pico_stdlib
        pico_time
        )
pico_add_extra_outputs(heap_benchmark_client)

pico_enable_stdio_usb(heap_benchmark_client 1)
pico_enable_stdio_uart(heap_benchmark_client 0)