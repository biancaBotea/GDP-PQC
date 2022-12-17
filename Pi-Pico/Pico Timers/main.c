#include <stdio.h>
#include "pico/stdlib.h"
#include "utime.h"
#include "systick.h"

void demo_utime(){
    microsecond_count_t* us_500 = (microsecond_count_t*) malloc(sizeof(microsecond_count_t));
    microsecond_count_t* us_1000 = (microsecond_count_t*) malloc(sizeof(microsecond_count_t));

    init_utime(us_500);
    init_utime(us_1000);

    begin_utime(us_500);
    begin_utime(us_1000);
    for(int a = 0; a<3; ++a){
        busy_wait_ms(500);
        split_utime(us_500);
        busy_wait_ms(500);
        split_utime(us_500);
        split_utime(us_1000);
    }
    busy_wait_ms(500);
    end_utime(us_500);
    busy_wait_ms(500);
    end_utime(us_1000);

    print_utime(us_500);
    print_utime(us_1000);
}

int main(){
    //Init stdio Output
    stdio_init_all();

    demo_utime();
    return 0;
}