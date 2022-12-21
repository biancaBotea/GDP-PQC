cmake_minimum_required(VERSION 3.13)

include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

project(flash C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

add_executable(${PROJECT_NAME}
    flashobj.h
    flash.h
    memobj.h
    main.c
)

pico_add_extra_outputs(${PROJECT_NAME})

target_link_libraries(${PROJECT_NAME}
    pico_stdlib
    hardware_flash
)

pico_enable_stdio_usb(${PROJECT_NAME} 0)
pico_enable_stdio_uart(${PROJECT_NAME} 1)