#include "pqc-pico/stats.h"

int main(){
    stdio_init_all();
    busy_wait_ms(300);
    
    
    stat_t* s = (stat_t*) malloc(sizeof(stat_t));
    init_stat(s);

    add_stat(s,3.3);
    add_stat(s,5.5769);
    add_stat(s,10);
    add_stat(s,6.53);
    add_stat(s,1.153);
    
    print_stat(s);
    print_conf_stat(s,95);
    free_stat(s);
    return 0;
}