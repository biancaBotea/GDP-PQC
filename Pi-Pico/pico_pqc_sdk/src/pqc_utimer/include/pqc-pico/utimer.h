#include <stdio.h>
#include <stdlib.h>
#include "pico/stdlib.h"

#define MAX_UTIMER_SPLITS 64

typedef struct {
    uint64_t ut_init;
    uint64_t ut_end;
    uint64_t ut_diff;

    size_t size_ut_splits;
    uint64_t* ut_splits;

    size_t size_ut_diffs;
    uint64_t* ut_diffs;
} microsecond_count_t;

void init_utimer(microsecond_count_t* us);

static void new_utimer(microsecond_count_t* us, uint64_t ut);
void begin_utimer(microsecond_count_t* us);

void split_utimer(microsecond_count_t* us);
void end_utime(microsecond_count_t* us);

void free_utime(microsecond_count_t* us);

void print_utime(microsecond_count_t* us);

void demo_utime();