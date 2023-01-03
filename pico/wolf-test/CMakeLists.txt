cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(wolf-test C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
pico_sdk_init()



add_executable(Benchmark
        Benchmark.c
)
        

#target_link_libraries(Benchmark PUBLIC /home/pi57/pico/wolf-test/libwolfssl.a pico_stdlib)
target_link_libraries(Benchmark PUBLIC pico_stdlib)

target_include_directories(Benchmark PUBLIC /home/pi57/oqs/wolfssl-arm/include /home/pi57/oqs/liboqs-arm)

# create map/bin/hex file etc.
pico_add_extra_outputs(Benchmark)

