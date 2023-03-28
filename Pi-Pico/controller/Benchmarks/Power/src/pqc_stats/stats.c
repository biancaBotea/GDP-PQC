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

void init_statobj(stat_obj_t* so, const char* label, stat_t* st, int conf_pc){
    so->label = strdup(label);
    so->mean = mean_stat(st);
    so->sd = sd_stat(st);
    so->p = conf_pc;
    so->ci = conf_stat(st,conf_pc);
    so->n = st->n;
}

void print_statobj(stat_obj_t* so){
    printf("mean=%f,sd=%f,ci=%f,p=0.%d,n=%zu\n",so->mean,so->sd,so->ci,so->p,so->n);
}

void print_statobj_csv(stat_obj_t* so){
    printf("%s, %f, %f, 0.%d, %zu\n",
        so->label,
        so->mean,
        so->ci,
        so->p,
        so->n);
}

void free_statobj(stat_obj_t* so){
    free(so);
}

void init_csv(csv_t* csv, char* HEADER_LABEL){
    csv->HEADER_LABEL = HEADER_LABEL;
    csv->size_so_l = 0;
    csv->so_l = NULL;
}

void add_csv(csv_t* csv, stat_obj_t* so){
    size_t temp_size_so_l = csv->size_so_l + 1;
    size_t head_so_l = temp_size_so_l - 1;
    stat_obj_t** temp_so_l = realloc(csv->so_l, temp_size_so_l * sizeof(stat_obj_t*));
    if(temp_so_l != NULL){
        csv->size_so_l = temp_size_so_l;
        csv->so_l = temp_so_l;
        csv->so_l[head_so_l] = so;
    }
    else{
        printf("Could not allocate memory for new CSV statobj");
        return;
    }
}

void print_csv(csv_t* csv){
    char* header = strcat(csv->HEADER_LABEL, HEADER_PARTIAL_STATOBJ_CSV);
    printf("%s",header);
    for(size_t row = 0; row< csv->size_so_l; ++row){
        print_statobj_csv(csv->so_l[row]);
    }
    printf("\n");
}

void free_csv(csv_t* csv){
    for(size_t so = 0; so<csv->size_so_l; ++so){
        free(csv->so_l[so]->label);
        free(csv->so_l[so]);
        csv->so_l[so] = NULL;
    }
    free(csv->so_l);
    csv->so_l = NULL;
    free(csv);
    csv = NULL;
}