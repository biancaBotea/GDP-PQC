#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "pico/stdlib.h"
#include "hardware/structs/systick.h"
#include "hardware/exception.h"

#define MAX_STSTICK_CT 8
#define MAX_SYSTICK_SPLITS 64

typedef struct systick_count{
    uint64_t st_init;
    uint64_t st_end;
    uint64_t st_diff;

    size_t size_st_splits;
    uint64_t* st_splits;

    size_t size_st_diffs;
    uint64_t* st_diffs;
} systick_count_t;

typedef struct systick_list{
    size_t size_st_list;
    systick_count_t** st_list; 
} systick_list_t;

systick_list_t st_l;

typedef struct systick_reg{
    bool init;
    systick_hw_t* st;
    exception_handler_t st_ex;

} systick_reg_t;

systick_reg_t sr = {.init=false};

void handle_systick(){

}

void init_systick_reg(){
    sr.init = true;
    sr.st = systick_hw;
    sr.st_ex = (exception_handler_t) handle_systick;

    /*SYST_RVR - SysTick Reload Value Register*/
    uint32_t SYSTICK_MAX = 0x00FFFFFF;
    sr.st->rvr &= M0PLUS_SYST_RVR_BITS & SYSTICK_MAX;

    /*SYST_CSR - SysTick Current Value Register*/
    sr.st->cvr &= M0PLUS_SYST_CVR_CURRENT_BITS & 0;

    /*SYST_CSR - SysTick Control and Status Register*/
    sr.st->csr |= M0PLUS_SYST_CSR_TICKINT_BITS;
    sr.st->csr |= M0PLUS_SYST_CSR_CLKSOURCE_BITS;
    sr.st->csr |= M0PLUS_SYST_CSR_ENABLE_BITS;

    st_l.size_st_list = 0;
    st_l.st_list = NULL;
}

void init_systick(systick_count_t* st){
    if(sr.init == false){init_systick_reg();}
    st->st_init = 0;
    st->st_end = 0;    
    st->st_diff = 0;
    st->size_st_splits = 0;
    st->st_splits = NULL;
    st->size_st_diffs = 0;
    st->st_diffs = NULL;
}

void begin_systick(systick_count_t* st){
    size_t temp_size_st_list = st_l.size_st_list + 1;
    size_t head_st_list = st_l.size_st_list;

    systick_count_t** temp_st_list = realloc(st_l.st_list,temp_size_st_list * sizeof(systick_count_t*));
    if(temp_st_list != NULL){
        st_l.st_list = temp_st_list;
        st_l.st_list[head_st_list] = st;
        st_l.size_st_list +=1;
    }
    else{
        printf("Could not reallocate memory for new systick in list.\n");
        return;
    }
}

void split_systick(systick_count_t* st){

}

void end_systick(systick_count_t* st){
    //make copy of old list
    systick_count_t** old_st_list = malloc(st_l.size_st_list * sizeof(systick_count_t*));
    for(int s = 0; s<st_l.size_st_list; ++s){
        old_st_list[s] = st_l.st_list[s];
    }
    memcpy(old_st_list, st_l.st_list, st_l.size_st_list);
    //reallocate list to temporary pointer
    size_t temp_size_st_list = st_l.size_st_list - 1;
    systick_count_t** temp_st_list = realloc(st_l.st_list,temp_size_st_list * sizeof(systick_count_t*));
    if(temp_st_list != NULL){
        //assign list pointer to new allocation
        st_l.st_list = temp_st_list;
        //search old list for index to remove
        size_t st_index = 0;
        for(int s = 0; s<st_l.size_st_list; ++s){
           if(old_st_list[s] == st)
                {
                    st_index = s; 
                    printf("%p at index %d\n",old_st_list[s],s);
                    break;}
        }
        //pass through old list and copy elements but for one to skip 
        int i = 0;
        for(int s = 0; s<st_l.size_st_list; ++s){
            if(s != st_index)
            {
                st_l.st_list[i] = old_st_list[s];
                ++i;
            }
        }
        //shrink list
        st_l.size_st_list = temp_size_st_list;
        
    }
    else{
        printf("Could not reallocate memory to remove systick from list.\n");
    }
    free(old_st_list);
}

void free_systick(systick_count_t* st){

}

void print_systick(systick_count_t* st){
    printf("Timer has address %p\n", st);
}

void print_systick_list(){
    printf("List has %zu timers",st_l.size_st_list);
    if(st_l.size_st_list > 0){
        printf(", with addresses: ");
        for(int s = 0; s<st_l.size_st_list; ++s){
            printf("%p ",st_l.st_list[s]);
        }
    }
    printf("\n");
}

void demo_systick_list(){
    systick_count_t* st0 = (systick_count_t*) malloc(sizeof(microsecond_count_t));
    init_systick(st0);
    begin_systick(st0);

    systick_count_t* st1 = (systick_count_t*) malloc(sizeof(microsecond_count_t));
    init_systick(st1);
    begin_systick(st1);

    systick_count_t* st2 = (systick_count_t*) malloc(sizeof(microsecond_count_t));
    init_systick(st2);
    begin_systick(st2);

    print_systick(st0);
    print_systick(st1);
    print_systick(st2);
    print_systick_list();

    end_systick(st0);
    print_systick(st0);
    print_systick_list();

    end_systick(st2);
    print_systick(st2);
    print_systick_list();

    end_systick(st1);
    print_systick(st1);
    print_systick_list();
}