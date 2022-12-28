#include <stdio.h>
#include <stdlib.h>
#include "pico/stdlib.h"

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

void init_utime(microsecond_count_t* us){
    us->ut_init = 0;
    us->ut_end = 0;
    us->ut_diff = 0;

    us->size_ut_splits = 0;
    us->ut_splits = NULL;

    us->size_ut_diffs = 0;
    us->ut_diffs = NULL;
}

//struct helper function
static void new_utime(microsecond_count_t* us, uint64_t ut){
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

void begin_utime(microsecond_count_t* us){
    us->ut_init = time_us_64();
    new_utime(us,us->ut_init);
}

void split_utime(microsecond_count_t* us){
    if(us->size_ut_splits <= MAX_UTIME_SPLITS){
        new_utime(us,time_us_64());
    }
    else{
        printf("MAX_UTIME_SPLITS Reached: %u",MAX_UTIME_SPLITS);
    }
}

void end_utime(microsecond_count_t* us){
    us->ut_end = time_us_64();
    new_utime(us,us->ut_end);
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

void free_utime(microsecond_count_t* us){
    free(us->ut_diffs);
    free(us->ut_splits);
    free(us);
}

void print_utime(microsecond_count_t* us){
    printf("Start utime: %llu\nEnd utime: %llu\nDiff utime: %llu\n", \
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