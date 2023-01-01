add_executable(test_csv test_csv.c)

target_link_libraries(test_csv PUBLIC
    pqc_stats)

pico_add_extra_outputs(test_csv)

pico_enable_stdio_usb(test_stats 0)
pico_enable_stdio_uart(test_stats 1)