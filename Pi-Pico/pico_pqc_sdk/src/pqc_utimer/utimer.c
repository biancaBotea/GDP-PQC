#include "pqc-pico/utimer.h"

void init_utimer(microsecond_count_t* us){
    us->ut_init = 0;
    us->ut_end = 0;
    us->ut_diff = 0;

    us->size_ut_splits = 0;
    us->ut_splits = NULL;

    us->size_ut_diffs = 0;
    us->ut_diffs = NULL;
}

//struct helper function
static void new_utimer(microsecond_count_t* us, uint64_t ut){
    us->size_ut_splits +=1;
    size_t head_ut_splits = us->size_ut_splits - 1;
    uint64_t* new_ut_splits = realloc(us->ut_splits, us->size_ut_splits * sizeof(uint64_t));
    if(new_ut_splits != NULL){
        us->ut_splits = new_ut_splits;
        us->ut_splits[head_ut_splits] = ut;
    }
    else{
        printf("Could not allocate new memory for split.\n");
        return;
    }
}

void begin_utimer(microsecond_count_t* us){
    us->ut_init = time_us_64();
    new_utimer(us,us->ut_init);
}

void split_utimer(microsecond_count_t* us){
    if(us->size_ut_splits <= MAX_UTIMER_SPLITS){
        new_utimer(us,time_us_64());
    }
    else{
        printf("MAX_UTIMER_SPLITS Reached: %u",MAX_UTIMER_SPLITS);
    }
}

void end_utimer(microsecond_count_t* us){
    us->ut_end = time_us_64();
    new_utimer(us,us->ut_end);
    us->ut_diff = us->ut_end - us->ut_init;
    
    us->size_ut_diffs = us->size_ut_splits - 1;
    us->ut_diffs = (uint64_t*) malloc(us->size_ut_diffs * sizeof(uint64_t));
    if(us->ut_diffs != NULL){
        for(int d = 0; d<us->size_ut_diffs; ++d){
            us->ut_diffs[d] = us->ut_splits[d+1] - us->ut_splits[d];
        }
    }
    else{
        printf("Could not allocate memory for split diffs");
    }
}

void free_utimer(microsecond_count_t* us){
    free(us->ut_diffs);
    free(us->ut_splits);
    free(us);
}

void print_utimer(microsecond_count_t* us){
    printf("Start utimer: %llu\nEnd utimer: %llu\nDiff utimer: %llu\n", \
        us->ut_init, \
        us->ut_end, \
        us->ut_diff);
    printf("ut splits:\n");
    for(int s = 0; s < us->size_ut_splits; ++s){
        printf("%llu\n",us->ut_splits[s]);
    }

    printf("ut diffs:\n");
    for(int d = 0; d < us->size_ut_diffs; ++d){
        printf("%llu\n",us->ut_diffs[d]);
    }
}

void demo_utime(){
    microsecond_count_t* us_500 = (microsecond_count_t*) malloc(sizeof(microsecond_count_t));
    microsecond_count_t* us_1000 = (microsecond_count_t*) malloc(sizeof(microsecond_count_t));

    init_utimer(us_500);
    init_utimer(us_1000);

    begin_utimer(us_500);
    begin_utimer(us_1000);
    for(int a = 0; a<3; ++a){
        busy_wait_ms(500);
        split_utimer(us_500);
        busy_wait_ms(500);
        split_utimer(us_500);
        split_utimer(us_1000);
    }
    busy_wait_ms(500);
    end_utimer(us_500);
    busy_wait_ms(500);
    end_utimer(us_1000);

    print_utimer(us_500);
    print_utimer(us_1000);
}