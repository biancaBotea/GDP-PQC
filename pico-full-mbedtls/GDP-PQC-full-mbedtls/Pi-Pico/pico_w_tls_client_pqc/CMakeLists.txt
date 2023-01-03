cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(pico_w_tls_client_pqc C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)
set(PICO_BOARD pico_w)
pico_sdk_init()

add_executable(pico_w_tls_client_pqc
        pico_w_tls_client_pqc.c
        )
target_compile_definitions(pico_w_tls_client_pqc PRIVATE
        WIFI_SSID=\"${WIFI_SSID}\"
        WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
        )
target_include_directories(pico_w_tls_client_pqc PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/.. # for our common lwipopts
        )
target_link_libraries(pico_w_tls_client_pqc
        pico_cyw43_arch_lwip_threadsafe_background
        pico_lwip_mbedtls
        pico_mbedtls
        pico_stdlib
        )
pico_add_extra_outputs(pico_w_tls_client_pqc)

pico_enable_stdio_usb(pico_w_tls_client_pqc 0)
pico_enable_stdio_uart(pico_w_tls_client_pqc 1)
