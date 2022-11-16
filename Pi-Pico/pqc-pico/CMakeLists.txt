cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(picow_tls_client C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)
set(PICO_BOARD pico_w)
pico_sdk_init()

add_executable(picow_tls_client
        picow_tls_client.c
        )
target_compile_definitions(picow_tls_client PRIVATE
        WIFI_SSID=\"${WIFI_SSID}\"
        WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
        )

target_include_directories(picow_tls_client PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/.. # for our common lwipopts
        )
target_link_libraries(picow_tls_client
        pico_cyw43_arch_lwip_threadsafe_background
        pico_lwip_mbedtls
        pico_mbedtls
        pico_stdlib
        )
pico_add_extra_outputs(picow_tls_client)

pico_enable_stdio_usb(picow_tls_client 0)
pico_enable_stdio_uart(picow_tls_client 1)
