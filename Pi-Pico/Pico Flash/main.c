#include <stdio.h>
#include "flash.h"

int main(){
    stdio_init_all();
    int ret;
    ret = demo_flasharray();
    return ret;
}