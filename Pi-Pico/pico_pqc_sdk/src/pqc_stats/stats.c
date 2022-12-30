#include "pqc-pico/stats.h"

void init_stat(stat_t* st){
    st->x = (float) 0;
    st->x2 = (float) 0;
    st->n = 0;
}

void add_stat(stat_t* st, float x){
    st->x += x;
    st->x2 += pow(x,2);
    st->n+=1;
}

inline float mean_stat(stat_t* st){
    return st->x / st->n;
}

static inline float __var_stat(stat_t* st){
    return st->x2 / st->n - pow(mean_stat(st),2);
}

inline float sd_stat(stat_t* st){
    return sqrt(__var_stat(st));
}

static inline float __sem_stat(stat_t* st){
    return sd_stat(st) / sqrt(st->n);
}

float conf_stat(stat_t* st, int conf_pc){
    float z;
    switch(conf_pc){
        case 50: z = 0.67449; break;
        case 75: z = 1.15035; break;
        case 90: z = 1.64485; break;
        case 95: z = 1.95996; break;
        case 97: z = 2.17009; break;
        case 99: z = 2.57583; break;
        case 999: z = 3.29053; break;
        default: z = 1.95996; break;
    }
    return z * __sem_stat(st);
} 

inline void print_stat(stat_t* st){
    printf("mean=%.3f sd=%.3f n=%zu\n",mean_stat(st),sd_stat(st),st->n);
}

inline void print_conf_stat(stat_t* st, int conf_pc){
    printf("mean=%.3f ci=%.3f p=0.%d n=%zu\n",mean_stat(st),conf_stat(st,conf_pc),conf_pc,st->n);
}

void free_stat(stat_t* st){
    free(st);
}

void init_statobj(stat_obj_t* so, stat_t* st, int conf_pc){
    so->mean = mean_stat(st);
    so->sd = sd_stat(st);
    so->p = conf_pc;
    so->ci = conf_stat(st,conf_pc);
    so->n = st->n;
}

void print_statobj(stat_obj_t* so){
    printf("mean=%f,sd=%f,ci=%f,p=0.%d,n=%zu\n",
        so->mean,
        so->sd,
        so->ci,
        so->p,
        so->n);
}

void free_statobj(stat_obj_t* so){
    free(so);
}