#include <stdio.h>
#include <stdlib.h>
#include "pico/stdlib.h"

#define MAX_UTIME_CT 8
#define MAX_UTIME_SPLITS 64

typedef struct {
    uint64_t ut_init;
    uint64_t ut_end;
    uint64_t ut_diff;

    size_t size_ut_splits;
    uint64_t* ut_splits;

    size_t size_ut_diffs;
    uint64_t* ut_diffs;
} microsecond_count_t;

void init_utime(microsecond_count_t* us_ct){
    us_ct->ut_init = 0;
    us_ct->ut_end = 0;
    us_ct->ut_diff = 0;

    us_ct->size_ut_splits = 0;
    us_ct->ut_splits = NULL;

    us_ct->size_ut_diffs = 0;
    us_ct->ut_diffs = NULL;
}

//struct helper function
void new_utime(microsecond_count_t* us_ct, uint64_t ut){
    us_ct->size_ut_splits +=1;
    size_t head_ut_splits = us_ct->size_ut_splits - 1;
    uint64_t* new_ut_splits = realloc(us_ct->ut_splits, us_ct->size_ut_splits * sizeof(uint64_t));
    if(new_ut_splits != NULL){
        us_ct->ut_splits = new_ut_splits;
        us_ct->ut_splits[head_ut_splits] = ut;
    }
    else{
        printf("Could not allocate new memory for split.\n");
        return;
    }
}

void begin_utime(microsecond_count_t* us_ct){
    us_ct->ut_init = time_us_64();
    new_utime(us_ct,us_ct->ut_init);
}

void split_utime(microsecond_count_t* us_ct){
    if(us_ct->size_ut_splits <= MAX_UTIME_SPLITS){
        new_utime(us_ct,time_us_64());
    }
    else{
        printf("MAX_UTIME_SPLITS Reached: %u",MAX_UTIME_SPLITS);
    }
}

void end_utime(microsecond_count_t* us_ct){
    us_ct->ut_end = time_us_64();
    new_utime(us_ct,us_ct->ut_end);
    us_ct->ut_diff = us_ct->ut_end - us_ct->ut_init;
    
    us_ct->size_ut_diffs = us_ct->size_ut_splits - 1;
    us_ct->ut_diffs = (uint64_t*) malloc(us_ct->size_ut_diffs * sizeof(uint64_t));
    if(us_ct->ut_diffs != NULL){
        for(int d = 0; d<us_ct->size_ut_diffs; ++d){
            us_ct->ut_diffs[d] = us_ct->ut_splits[d+1] - us_ct->ut_splits[d];
        }
    }
    else{
        printf("Could not allocate memory for split diffs");
    }
}

void free_utime(microsecond_count_t* us_ct){

}

void print_utime(microsecond_count_t* us_ct){
    printf("Start utime: %llu\nEnd utime: %llu\nDiff utime: %llu\n", \
        us_ct->ut_init, \
        us_ct->ut_end, \
        us_ct->ut_diff);
    printf("ut splits:\n");
    for(int s = 0; s < us_ct->size_ut_splits; ++s){
        printf("%llu\n",us_ct->ut_splits[s]);
    }

    printf("ut diffs:\n");
    for(int d = 0; d < us_ct->size_ut_diffs; ++d){
        printf("%llu\n",us_ct->ut_diffs[d]);
    }
}

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