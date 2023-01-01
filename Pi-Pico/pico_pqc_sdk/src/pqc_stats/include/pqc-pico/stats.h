#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"

#define HEADER_PARTIAL_STATOBJ_CSV ", MEAN, CI, P, N\n"

typedef struct {
    float x;
    float x2;
    size_t n;
} stat_t;

typedef struct {
    char* label;
    float mean;
    float sd;
    float ci;
    int p;
    size_t n;
} stat_obj_t;

typedef struct {
    char* HEADER_LABEL;
    size_t size_so_l;
    stat_obj_t** so_l;
} csv_t;

void init_stat(stat_t* st);
void add_stat(stat_t* st, float x);
extern float mean_stat(stat_t* st);
extern float sd_stat(stat_t* st);
float conf_stat(stat_t* st, int conf_pc);
extern void print_stat(stat_t* st);
extern void print_conf_stat(stat_t* st, int conf_pc);
void free_stat(stat_t* st);

void init_statobj(stat_obj_t* so, const char* label, stat_t* st, int conf_pc);
void print_statobj(stat_obj_t* so);
void print_statobj_csv(stat_obj_t* so);
void free_statobj(stat_obj_t* so);

void init_csv(csv_t* csv, char* HEADER_LABEL);
void add_csv(csv_t* csv, stat_obj_t* so);
void print_csv(csv_t* csv);
void free_csv(csv_t* csv);