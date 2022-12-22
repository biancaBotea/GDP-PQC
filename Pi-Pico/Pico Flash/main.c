#include <stdio.h>
#include "pico/stdlib.h"
#include "flashmem.h"

int main(){
    stdio_init_all();
    demo_flash();
    return 0;
}