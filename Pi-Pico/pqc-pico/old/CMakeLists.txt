cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(pqc-pico C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

if(PICO_SDK_VERSION_STRING VERSION_LESS "1.3.0")
    message(FATAL_ERROR "Raspberry Pi Pico SDK version 1.3.0 (or later) required. Your version of ${PICO_SDK_VERSION_STRING}")
endif()


pico_sdk_init()

include(example_auto_set_url.cmake)

add_compile_options(-Wall 
-Wno-format
-Wno-unused-function
-Wno-maybe-uninitialized
)

add_executable(picow_tls_client.c)

target_compile_definitions(pqc-pico PRIVATE
    WIFI_SSID=\"${WIFI_SSID}\"
    WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
)

target_include_directories(pqc-pico PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}
)

target_link_libraries(pqc-pico
    pico_cyw43_arch_lwip_poll
    pico_lwip_mbedtls
    pico_mbedtls
    pico_stdlib
)

# if(PICO_CYW43_SUPPORTED)
#     if(NOT TARGET pico_cyw43_arch)
#         message("Target not set as pico_cyw43_arch, Target:${TARGET}")
#     else()
#         set(WIFI_SSID "${WIFI_SSID}" CACHE INTERNAL "WiFi SSID for compilation.")
#         set(WIFI_PASSWORD "${WIFI_PASSWORD}" CACHE INTERNAL "WiFi password for compilatio.n")

#         if("${WIFI_SSID}" STREQUAL "")
#             message("Skipping compilation; WiFi SSID not set.")
#         elseif ("${WIFI_PASSWORD}" STREQUAL "")
#             message("Skipping compilation; Wifi Password not set.")
#         else()
#             add_executable(picow_tls_client.c)
#         endif()
#     endif()
# endif()

pico_add_extra_outputs(pqc-pico)

pico_enable_stdio_usb(pqc-pico 0)
pico_enable_stdio_uart(pqc-pico 1)