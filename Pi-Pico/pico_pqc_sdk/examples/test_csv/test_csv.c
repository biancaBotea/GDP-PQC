#include "pqc-pico/stats.h"

stat_obj_t* rand_obj(size_t num, int conf_pc){
    //track random number statistic
    stat_t* rand_stat = (stat_t*) malloc(sizeof(stat_t));
    init_stat(rand_stat);
    size_t nobj = 20;
    for(size_t n = 0; n < nobj; ++n){
        add_stat(rand_stat, rand() % 100);
    }
    //store stats in object
    stat_obj_t* obj = (stat_obj_t*) malloc(sizeof(stat_obj_t));
    char snum[5];
    snprintf(snum,sizeof snum,"%zu", num);
    char sconf[5];
    snprintf(sconf,sizeof sconf, "%d", conf_pc);
    char rand[] = "RAND_p=0.";
    char* rowlabel = strcat(rand,sconf);
    rowlabel = strcat(rowlabel,"_");
    rowlabel = strcat(rand,snum);
    init_statobj(obj,rowlabel,rand_stat,conf_pc);
    free_stat(rand_stat);
    return obj;
}

int main(){
    stdio_init_all();
    busy_wait_ms(30);

    char header_95[] = "RAND_0.95";
    char header_99[] = "RAND_0.99";
    char header_999[] = "RAND_0.999";
    csv_t* csv_95 = (csv_t*) malloc(sizeof(csv_t));
    csv_t* csv_99 = (csv_t*) malloc(sizeof(csv_t));
    csv_t* csv_999 = (csv_t*) malloc(sizeof(csv_t));
    init_csv(csv_95,header_95);
    init_csv(csv_99,header_99);
    init_csv(csv_999,header_999);

    size_t nrow = 11;
    for(size_t n = 1; n<nrow; ++n){
        stat_obj_t* rand_so_95 = rand_obj(n,95);
        stat_obj_t* rand_so_99 = rand_obj(n,99);
        stat_obj_t* rand_so_999 = rand_obj(n,999);
        add_csv(csv_95,rand_so_95);
        add_csv(csv_99,rand_so_99);
        add_csv(csv_999,rand_so_999);
    }
    print_csv(csv_95);
    print_csv(csv_99);
    print_csv(csv_999);

    free_csv(csv_95);
    free_csv(csv_99);
    free_csv(csv_999);
    return 0;
}