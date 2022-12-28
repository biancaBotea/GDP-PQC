#include "pqc-pico/utimer.h"
#include "pqc-pico/flash.h"
#include "pqc-pico/systick.h"

int main(){
    stdio_init_all();
    demo_utime();
    demo_flash();
    printf("Hello World!");
    return 0;
}