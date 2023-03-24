add_executable(test_stats test_stats.c)

target_link_libraries(test_stats PUBLIC
    pqc_stats)

pico_add_extra_outputs(test_stats)

pico_enable_stdio_usb(test_stats 0)
pico_enable_stdio_uart(test_stats 1)