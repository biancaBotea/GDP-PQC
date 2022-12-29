#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include "pico/stdlib.h"

typedef struct {
    float x;
    float x2;
    size_t n;
} stat_t;

void init_stat(stat_t* st);
void add_stat(stat_t* st, float x);
extern float mean_stat(stat_t* st);
extern float sd_stat(stat_t* st);
float conf_stat(stat_t* st, int conf_pc);
extern void print_stat(stat_t* st);
extern void print_conf_stat(stat_t* st, int conf_pc);
void free_stat(stat_t* st);
