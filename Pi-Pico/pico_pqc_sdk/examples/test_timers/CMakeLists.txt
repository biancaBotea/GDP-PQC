add_executable(test_timers
    test_timers.c
    )

target_link_libraries(test_timers PUBLIC 
    pqc_utimer
    pqc_systick
    pqc_flash)

pico_add_extra_outputs(test_timers)

pico_enable_stdio_usb(test_timers 0)
pico_enable_stdio_uart(test_timers 1)