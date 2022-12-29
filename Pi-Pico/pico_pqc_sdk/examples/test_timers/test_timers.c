#include "pqc-pico/utimer.h"
#include "pqc-pico/systick.h"

void init(){
    stdio_init_all();
    //wait for stdio init
    busy_wait_ms(300);
    init_systick_reg();
}

int main(){
    init();

    printf("--inline declarations, with inline (un)pause systick, with init dummy timer--\n");
    size_t mean_begin = 0;
    size_t mean_end = 0;
    size_t n = 500;
    for(size_t r = 0; r<n; ++r){
        systick_count_t* stp = (systick_count_t*) malloc(sizeof(systick_count_t));

        int ret = init_systick(stp);
        if(ret != 0){
            return ret;
        }

        microsecond_count_t* utp = (microsecond_count_t*) malloc(sizeof(microsecond_count_t));
        init_utimer(utp);

        // printf("Begin utimer: ");
        begin_systick(stp);
        global_pause_systick();
        begin_utimer(utp);
        global_unpause_systick();
        end_systick(stp);
        // print_systick(stp);
        mean_begin += stp->st_diff;

        // printf("End utimer: ");
        begin_systick(stp);
        global_pause_systick();
        end_utimer(utp);
        global_unpause_systick();
        end_systick(stp);
        mean_end += stp->st_diff;
        // print_systick(stp);   

        free_systick(stp);
        free_utimer(utp);
    }
    printf("mean begin: %f\nmean end: %f\n",(float)mean_begin/(float)n,(float)mean_end/(float)n);
    return 0;
}
