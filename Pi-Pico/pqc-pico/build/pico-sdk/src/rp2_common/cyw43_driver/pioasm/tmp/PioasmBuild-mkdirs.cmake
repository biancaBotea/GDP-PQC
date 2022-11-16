# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "C:/VSARM/sdk/pico/pico-sdk/tools/pioasm"
  "H:/Part 4 EEE/ELEC6200 Group Design Project/pqc-pico/build/pioasm"
  "H:/Part 4 EEE/ELEC6200 Group Design Project/pqc-pico/build/pico-sdk/src/rp2_common/cyw43_driver/pioasm"
  "H:/Part 4 EEE/ELEC6200 Group Design Project/pqc-pico/build/pico-sdk/src/rp2_common/cyw43_driver/pioasm/tmp"
  "H:/Part 4 EEE/ELEC6200 Group Design Project/pqc-pico/build/pico-sdk/src/rp2_common/cyw43_driver/pioasm/src/PioasmBuild-stamp"
  "H:/Part 4 EEE/ELEC6200 Group Design Project/pqc-pico/build/pico-sdk/src/rp2_common/cyw43_driver/pioasm/src"
  "H:/Part 4 EEE/ELEC6200 Group Design Project/pqc-pico/build/pico-sdk/src/rp2_common/cyw43_driver/pioasm/src/PioasmBuild-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "H:/Part 4 EEE/ELEC6200 Group Design Project/pqc-pico/build/pico-sdk/src/rp2_common/cyw43_driver/pioasm/src/PioasmBuild-stamp/${subDir}")
endforeach()
