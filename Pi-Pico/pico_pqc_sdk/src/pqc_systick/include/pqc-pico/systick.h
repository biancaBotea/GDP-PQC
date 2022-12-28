#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include "pico/stdlib.h"
#include "hardware/structs/systick.h"
#include "hardware/exception.h"

#define SYSTICK_MAX 0x00FFFFFF
#define MAX_STSTICK_CT 8
#define MAX_SYSTICK_SPLITS 64

typedef struct systick_count{
    uint32_t st_init_csr;
    uint32_t st_end_csr;

    uint64_t st_diff;
    uint64_t st_count;

    size_t size_st_splits;
    uint64_t* st_splits;

    size_t size_st_diffs;
    uint64_t* st_diffs;
} systick_count_t;

typedef struct systick_list{
    size_t size_st_list;
    systick_count_t** st_list; 
} systick_list_t;

typedef struct systick_reg{
    bool init;
    systick_hw_t* st;
    exception_handler_t st_ex;

} systick_reg_t;

static void handle_systick();
void init_systick_reg();
int init_systick(systick_count_t* st);
static void __new_systick(systick_count_t* st, uint64_t t);
void begin_systick(systick_count_t* st);
void split_systick(systick_count_t* st);
void end_systick(systick_count_t* st);
void demo_systick_splits();
void demo_systick_multi();
void demo_systick_list();