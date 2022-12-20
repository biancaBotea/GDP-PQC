#include <stdio.h>
#include "pico/stdlib.h"
#include "utime.h"
#include "systick.h"

int main(){
    //Init stdio Output
    stdio_init_all();
    demo_systick_splits();
    return 0;
}