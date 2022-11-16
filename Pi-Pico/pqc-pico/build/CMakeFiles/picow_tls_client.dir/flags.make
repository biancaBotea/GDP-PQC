# CMAKE generated file: DO NOT EDIT!
# Generated by "MinGW Makefiles" Generator, CMake Version 3.23

# compile ASM with C:/VSARM/armcc/10 2021.10/bin/arm-none-eabi-gcc.exe
# compile C with C:/VSARM/armcc/10 2021.10/bin/arm-none-eabi-gcc.exe
# compile CXX with C:/VSARM/armcc/10 2021.10/bin/arm-none-eabi-g++.exe
ASM_DEFINES = -DCYW43_LWIP=1 -DLIB_PICO_BIT_OPS=1 -DLIB_PICO_BIT_OPS_PICO=1 -DLIB_PICO_CYW43_ARCH=1 -DLIB_PICO_DIVIDER=1 -DLIB_PICO_DIVIDER_HARDWARE=1 -DLIB_PICO_DOUBLE=1 -DLIB_PICO_DOUBLE_PICO=1 -DLIB_PICO_FLOAT=1 -DLIB_PICO_FLOAT_PICO=1 -DLIB_PICO_INT64_OPS=1 -DLIB_PICO_INT64_OPS_PICO=1 -DLIB_PICO_MALLOC=1 -DLIB_PICO_MBEDTLS=1 -DLIB_PICO_MEM_OPS=1 -DLIB_PICO_MEM_OPS_PICO=1 -DLIB_PICO_PLATFORM=1 -DLIB_PICO_PRINTF=1 -DLIB_PICO_PRINTF_PICO=1 -DLIB_PICO_RUNTIME=1 -DLIB_PICO_STANDARD_LINK=1 -DLIB_PICO_STDIO=1 -DLIB_PICO_STDIO_UART=1 -DLIB_PICO_STDLIB=1 -DLIB_PICO_SYNC=1 -DLIB_PICO_SYNC_CORE=1 -DLIB_PICO_SYNC_CRITICAL_SECTION=1 -DLIB_PICO_SYNC_MUTEX=1 -DLIB_PICO_SYNC_SEM=1 -DLIB_PICO_TIME=1 -DLIB_PICO_UNIQUE_ID=1 -DLIB_PICO_UTIL=1 -DMBEDTLS_CONFIG_FILE=\"mbedtls_config.h\" -DPICO_BOARD=\"pico_w\" -DPICO_BUILD=1 -DPICO_CMAKE_BUILD_TYPE=\"Debug\" -DPICO_COPY_TO_RAM=0 -DPICO_CXX_ENABLE_EXCEPTIONS=0 -DPICO_CYW43_ARCH_THREADSAFE_BACKGROUND=1 -DPICO_NO_FLASH=0 -DPICO_NO_HARDWARE=0 -DPICO_ON_DEVICE=1 -DPICO_TARGET_NAME=\"picow_tls_client\" -DPICO_USE_BLOCKED_RAM=0 -DWIFI_PASSWORD=\"iHb53kKlQcSj\" -DWIFI_SSID=\"SOTON-IoT\"

ASM_INCLUDES = -I"H:\Part 4 EEE\ELEC6200 Group Design Project\pqc-pico" -I"H:\Part 4 EEE\ELEC6200 Group Design Project\pqc-pico\.." -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_cyw43_arch\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_unique_id\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_flash\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_base\include -I"H:\Part 4 EEE\ELEC6200 Group Design Project\pqc-pico\build\generated\pico_base" -IC:\VSARM\sdk\pico\pico-sdk\src\boards\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_platform\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2040\hardware_regs\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_base\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2040\hardware_structs\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_claim\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_sync\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_bootrom\include -I"H:\Part 4 EEE\ELEC6200 Group Design Project\pqc-pico\build\pico-sdk\src\rp2_common\cyw43_driver" -IC:\VSARM\sdk\pico\pico-sdk\lib\cyw43-driver\src -IC:\VSARM\sdk\pico\pico-sdk\lib\cyw43-driver\firmware -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_stdlib\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_gpio\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_irq\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_sync\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_time\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_timer\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_util\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_uart\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_divider\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_runtime\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_clocks\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_resets\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_pll\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_vreg\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_watchdog\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_xosc\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_printf\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_bit_ops\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_divider\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_double\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_int64_ops\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_float\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_malloc\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\boot_stage2\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_binary_info\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_stdio\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_stdio_uart\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_pio\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_dma\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_exception\include -IC:\VSARM\sdk\pico\pico-sdk\lib\lwip\src\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_lwip\include -IC:\VSARM\sdk\pico\pico-sdk\lib\mbedtls\include -IC:\VSARM\sdk\pico\pico-sdk\lib\mbedtls\library

ASM_FLAGS = -mcpu=cortex-m0plus -mthumb -Og -g -ffunction-sections -fdata-sections

C_DEFINES = -DCYW43_LWIP=1 -DLIB_PICO_BIT_OPS=1 -DLIB_PICO_BIT_OPS_PICO=1 -DLIB_PICO_CYW43_ARCH=1 -DLIB_PICO_DIVIDER=1 -DLIB_PICO_DIVIDER_HARDWARE=1 -DLIB_PICO_DOUBLE=1 -DLIB_PICO_DOUBLE_PICO=1 -DLIB_PICO_FLOAT=1 -DLIB_PICO_FLOAT_PICO=1 -DLIB_PICO_INT64_OPS=1 -DLIB_PICO_INT64_OPS_PICO=1 -DLIB_PICO_MALLOC=1 -DLIB_PICO_MBEDTLS=1 -DLIB_PICO_MEM_OPS=1 -DLIB_PICO_MEM_OPS_PICO=1 -DLIB_PICO_PLATFORM=1 -DLIB_PICO_PRINTF=1 -DLIB_PICO_PRINTF_PICO=1 -DLIB_PICO_RUNTIME=1 -DLIB_PICO_STANDARD_LINK=1 -DLIB_PICO_STDIO=1 -DLIB_PICO_STDIO_UART=1 -DLIB_PICO_STDLIB=1 -DLIB_PICO_SYNC=1 -DLIB_PICO_SYNC_CORE=1 -DLIB_PICO_SYNC_CRITICAL_SECTION=1 -DLIB_PICO_SYNC_MUTEX=1 -DLIB_PICO_SYNC_SEM=1 -DLIB_PICO_TIME=1 -DLIB_PICO_UNIQUE_ID=1 -DLIB_PICO_UTIL=1 -DMBEDTLS_CONFIG_FILE=\"mbedtls_config.h\" -DPICO_BOARD=\"pico_w\" -DPICO_BUILD=1 -DPICO_CMAKE_BUILD_TYPE=\"Debug\" -DPICO_COPY_TO_RAM=0 -DPICO_CXX_ENABLE_EXCEPTIONS=0 -DPICO_CYW43_ARCH_THREADSAFE_BACKGROUND=1 -DPICO_NO_FLASH=0 -DPICO_NO_HARDWARE=0 -DPICO_ON_DEVICE=1 -DPICO_TARGET_NAME=\"picow_tls_client\" -DPICO_USE_BLOCKED_RAM=0 -DWIFI_PASSWORD=\"iHb53kKlQcSj\" -DWIFI_SSID=\"SOTON-IoT\"

C_INCLUDES = -I"H:\Part 4 EEE\ELEC6200 Group Design Project\pqc-pico" -I"H:\Part 4 EEE\ELEC6200 Group Design Project\pqc-pico\.." -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_cyw43_arch\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_unique_id\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_flash\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_base\include -I"H:\Part 4 EEE\ELEC6200 Group Design Project\pqc-pico\build\generated\pico_base" -IC:\VSARM\sdk\pico\pico-sdk\src\boards\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_platform\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2040\hardware_regs\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_base\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2040\hardware_structs\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_claim\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_sync\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_bootrom\include -I"H:\Part 4 EEE\ELEC6200 Group Design Project\pqc-pico\build\pico-sdk\src\rp2_common\cyw43_driver" -IC:\VSARM\sdk\pico\pico-sdk\lib\cyw43-driver\src -IC:\VSARM\sdk\pico\pico-sdk\lib\cyw43-driver\firmware -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_stdlib\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_gpio\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_irq\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_sync\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_time\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_timer\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_util\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_uart\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_divider\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_runtime\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_clocks\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_resets\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_pll\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_vreg\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_watchdog\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_xosc\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_printf\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_bit_ops\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_divider\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_double\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_int64_ops\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_float\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_malloc\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\boot_stage2\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_binary_info\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_stdio\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_stdio_uart\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_pio\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_dma\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_exception\include -IC:\VSARM\sdk\pico\pico-sdk\lib\lwip\src\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_lwip\include -IC:\VSARM\sdk\pico\pico-sdk\lib\mbedtls\include -IC:\VSARM\sdk\pico\pico-sdk\lib\mbedtls\library

C_FLAGS = -mcpu=cortex-m0plus -mthumb -Og -g -ffunction-sections -fdata-sections -std=gnu11

CXX_DEFINES = -DCYW43_LWIP=1 -DLIB_PICO_BIT_OPS=1 -DLIB_PICO_BIT_OPS_PICO=1 -DLIB_PICO_CYW43_ARCH=1 -DLIB_PICO_DIVIDER=1 -DLIB_PICO_DIVIDER_HARDWARE=1 -DLIB_PICO_DOUBLE=1 -DLIB_PICO_DOUBLE_PICO=1 -DLIB_PICO_FLOAT=1 -DLIB_PICO_FLOAT_PICO=1 -DLIB_PICO_INT64_OPS=1 -DLIB_PICO_INT64_OPS_PICO=1 -DLIB_PICO_MALLOC=1 -DLIB_PICO_MBEDTLS=1 -DLIB_PICO_MEM_OPS=1 -DLIB_PICO_MEM_OPS_PICO=1 -DLIB_PICO_PLATFORM=1 -DLIB_PICO_PRINTF=1 -DLIB_PICO_PRINTF_PICO=1 -DLIB_PICO_RUNTIME=1 -DLIB_PICO_STANDARD_LINK=1 -DLIB_PICO_STDIO=1 -DLIB_PICO_STDIO_UART=1 -DLIB_PICO_STDLIB=1 -DLIB_PICO_SYNC=1 -DLIB_PICO_SYNC_CORE=1 -DLIB_PICO_SYNC_CRITICAL_SECTION=1 -DLIB_PICO_SYNC_MUTEX=1 -DLIB_PICO_SYNC_SEM=1 -DLIB_PICO_TIME=1 -DLIB_PICO_UNIQUE_ID=1 -DLIB_PICO_UTIL=1 -DMBEDTLS_CONFIG_FILE=\"mbedtls_config.h\" -DPICO_BOARD=\"pico_w\" -DPICO_BUILD=1 -DPICO_CMAKE_BUILD_TYPE=\"Debug\" -DPICO_COPY_TO_RAM=0 -DPICO_CXX_ENABLE_EXCEPTIONS=0 -DPICO_CYW43_ARCH_THREADSAFE_BACKGROUND=1 -DPICO_NO_FLASH=0 -DPICO_NO_HARDWARE=0 -DPICO_ON_DEVICE=1 -DPICO_TARGET_NAME=\"picow_tls_client\" -DPICO_USE_BLOCKED_RAM=0 -DWIFI_PASSWORD=\"iHb53kKlQcSj\" -DWIFI_SSID=\"SOTON-IoT\"

CXX_INCLUDES = -I"H:\Part 4 EEE\ELEC6200 Group Design Project\pqc-pico" -I"H:\Part 4 EEE\ELEC6200 Group Design Project\pqc-pico\.." -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_cyw43_arch\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_unique_id\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_flash\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_base\include -I"H:\Part 4 EEE\ELEC6200 Group Design Project\pqc-pico\build\generated\pico_base" -IC:\VSARM\sdk\pico\pico-sdk\src\boards\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_platform\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2040\hardware_regs\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_base\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2040\hardware_structs\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_claim\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_sync\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_bootrom\include -I"H:\Part 4 EEE\ELEC6200 Group Design Project\pqc-pico\build\pico-sdk\src\rp2_common\cyw43_driver" -IC:\VSARM\sdk\pico\pico-sdk\lib\cyw43-driver\src -IC:\VSARM\sdk\pico\pico-sdk\lib\cyw43-driver\firmware -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_stdlib\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_gpio\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_irq\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_sync\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_time\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_timer\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_util\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_uart\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_divider\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_runtime\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_clocks\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_resets\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_pll\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_vreg\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_watchdog\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_xosc\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_printf\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_bit_ops\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_divider\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_double\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_int64_ops\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_float\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_malloc\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\boot_stage2\include -IC:\VSARM\sdk\pico\pico-sdk\src\common\pico_binary_info\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_stdio\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_stdio_uart\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_pio\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_dma\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\hardware_exception\include -IC:\VSARM\sdk\pico\pico-sdk\lib\lwip\src\include -IC:\VSARM\sdk\pico\pico-sdk\src\rp2_common\pico_lwip\include -IC:\VSARM\sdk\pico\pico-sdk\lib\mbedtls\include -IC:\VSARM\sdk\pico\pico-sdk\lib\mbedtls\library

CXX_FLAGS = -mcpu=cortex-m0plus -mthumb -Og -g -ffunction-sections -fdata-sections -fno-exceptions -fno-unwind-tables -fno-rtti -fno-use-cxa-atexit -std=gnu++11

