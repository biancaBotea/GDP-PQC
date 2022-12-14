#include <stdio.h>
#include "pico/stdlib.h"
#include "hardware/exception.h"
#include "hardware/structs/systick.h"
#include "systick.h"

int main(){
    //Init stdio Output
    stdio_init_all();

    systick_hw_t* st = systick_hw;
    exception_handler_t (*st_h)(void) = &handle_systick;
    
    //Init SysTick Registers
    init_systick(st,st_h);

    //Loop Forever
    while(true){
        begin_systick(st);
        sleep_time(1);
        end_systick(st);
    }
    return 0;
}