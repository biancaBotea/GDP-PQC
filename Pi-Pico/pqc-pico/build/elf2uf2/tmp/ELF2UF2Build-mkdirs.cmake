# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "C:/VSARM/sdk/pico/pico-sdk/tools/elf2uf2"
  "H:/Part 4 EEE/ELEC6200 Group Design Project/pqc-pico/build/elf2uf2"
  "H:/Part 4 EEE/ELEC6200 Group Design Project/pqc-pico/build/elf2uf2"
  "H:/Part 4 EEE/ELEC6200 Group Design Project/pqc-pico/build/elf2uf2/tmp"
  "H:/Part 4 EEE/ELEC6200 Group Design Project/pqc-pico/build/elf2uf2/src/ELF2UF2Build-stamp"
  "H:/Part 4 EEE/ELEC6200 Group Design Project/pqc-pico/build/elf2uf2/src"
  "H:/Part 4 EEE/ELEC6200 Group Design Project/pqc-pico/build/elf2uf2/src/ELF2UF2Build-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "H:/Part 4 EEE/ELEC6200 Group Design Project/pqc-pico/build/elf2uf2/src/ELF2UF2Build-stamp/${subDir}")
endforeach()
