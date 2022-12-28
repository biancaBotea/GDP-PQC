#include "pqc-pico/systick.h"

systick_list_t st_l;

systick_reg_t sr = {.init=false};

static void handle_systick(){
    for(int st = 0; st < st_l.size_st_list; ++st){
        st_l.st_list[st]->st_count += 1;
    }
}

void init_systick_reg(){
    sr.init = true;
    sr.st = systick_hw;
    sr.st_ex = (exception_handler_t) handle_systick;
    exception_set_exclusive_handler(SYSTICK_EXCEPTION, sr.st_ex);

    /*SYST_RVR - SysTick Reload Value Register*/
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

int init_systick(systick_count_t* st){
    //Disable counter
    sr.st->csr &= ~M0PLUS_SYST_CSR_ENABLE_BITS;
    if(sr.init == false){
        printf("SysTick Registers not configured.");
        return -1;
    }

    st->st_init_csr = 0;
    st->st_end_csr = 0;    
    st->st_diff = 0;
    st->size_st_splits = 0;
    st->st_splits = NULL;
    st->size_st_diffs = 0;
    st->st_diffs = NULL;
    st->st_count = 0;

    //Re-enable counter
    sr.st->csr |= M0PLUS_SYST_CSR_ENABLE_BITS;
    return 0;
}

static void __new_systick(systick_count_t* st, uint64_t t){
    size_t temp_size_st_splits = st->size_st_splits + 1;
    size_t head_st_splits = temp_size_st_splits - 1;
    uint64_t* temp_st_splits = realloc(st->st_splits, temp_size_st_splits * sizeof(uint64_t));
    if(temp_st_splits != NULL){
        st->st_splits = temp_st_splits;
        st->st_splits[head_st_splits] = t;
        st->size_st_splits = temp_size_st_splits;
    }
    else{
        printf("Could not allocate new memory for split.\n");
        return;
    }
}

void begin_systick(systick_count_t* st){
    //Disable counter while capturing value
    sr.st->csr &= ~M0PLUS_SYST_CSR_ENABLE_BITS;

    if(st_l.size_st_list > MAX_STSTICK_CT){
        printf("MAX_SYSTICK_CT Reached: %u", MAX_STSTICK_CT);
        return;
    }

    //Store csr at init
    st->st_init_csr = (sr.st->cvr & M0PLUS_SYST_CVR_CURRENT_BITS);    
    __new_systick(st,0);
    
    //Register counter
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
    //Re-enable counter
    sr.st->csr |= M0PLUS_SYST_CSR_ENABLE_BITS;
}

void split_systick(systick_count_t* st){
    if(st->size_st_splits <= MAX_SYSTICK_SPLITS){
        sr.st->csr &= ~M0PLUS_SYST_CSR_ENABLE_BITS;
        uint32_t split_csr = sr.st->cvr & M0PLUS_SYST_CVR_CURRENT_BITS;
        uint64_t split_diff = st->st_init_csr + st->st_count*SYSTICK_MAX - split_csr;
        __new_systick(st,split_diff);
        sr.st->csr |= M0PLUS_SYST_CSR_ENABLE_BITS;
    }
    else{
        printf("MAX_SYSTICK_SPLITS Reached: %u",MAX_SYSTICK_SPLITS);
        return;
    }
}

void end_systick(systick_count_t* st){
    //Disable counter while capturing value
    sr.st->csr &= ~M0PLUS_SYST_CSR_ENABLE_BITS;

    //Store csr at end
    st->st_end_csr = sr.st->cvr & M0PLUS_SYST_CVR_CURRENT_BITS;

    //Calculate counter diff
    st->st_diff = st->st_init_csr + st->st_count*SYSTICK_MAX - st->st_end_csr;
    __new_systick(st,st->st_diff);

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
                    free(old_st_list);   
                    break;
                }
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
        free(old_st_list);
        return;
    }
    st->st_init_csr=0;
    st->st_end_csr=0;
    st->st_count=0;

    st->size_st_diffs = st->size_st_splits - 1;
    st->st_diffs= (uint64_t*) malloc(st->size_st_diffs * sizeof(uint64_t));
    if(st->st_diffs != NULL){
        for(int d = 0; d<st->size_st_diffs; ++d){
            st->st_diffs[d] = st->st_splits[d+1] - st->st_splits[d];
        }
    }
    else{
        printf("Could not allocate memory for split diffs.");
        return;
    }

    //Re-enable counter
    sr.st->csr |= M0PLUS_SYST_CSR_ENABLE_BITS;
}

void free_systick(systick_count_t* st){
    sr.st->csr &= ~M0PLUS_SYST_CSR_ENABLE_BITS;

    free(st->st_diffs);
    free(st->st_splits);
    free(st);

    sr.st->csr |= M0PLUS_SYST_CSR_ENABLE_BITS;
}

void print_systick(systick_count_t* st){
    printf("%llu Cycles\n",st->st_diff);
}

void print_systick_splits(systick_count_t* st){
    print_systick(st);
    printf("st splits:\n");
    for(int s = 0; s < st->size_st_splits; ++s){
        printf("%d:%llu\n",s,st->st_splits[s]);
    }
    printf("st diffs:\n");
    for(int d = 0; d< st->size_st_diffs; ++d){
        printf("%d->%d:%llu\n",d,d+1,st->st_diffs[d]);
    }
    printf("\n");
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

void demo_systick_splits(){
    init_systick_reg();

    systick_count_t* st1 = (systick_count_t*) malloc(sizeof(systick_count_t));
    systick_count_t* st10 = (systick_count_t*) malloc(sizeof(systick_count_t));
    init_systick(st1);
    init_systick(st10);

    begin_systick(st1);
    begin_systick(st10);
    for(int s10 = 0; s10<2; ++s10){
        for(int s1 = 0;s1<4;++s1){
            busy_wait_ms(1000);
            split_systick(st1);
        }
        split_systick(st10);
    }
    busy_wait_ms(5000);
    end_systick(st1);
    end_systick(st10);

    print_systick_splits(st1);
    print_systick_splits(st10);

    free_systick(st10);
    free_systick(st1);
}

void demo_systick_multi(){
    init_systick_reg();

    systick_count_t* st0 = (systick_count_t*) malloc(sizeof(systick_count_t));
    systick_count_t* st10 = (systick_count_t*) malloc(sizeof(systick_count_t));
    init_systick(st0);
    init_systick(st10);
    begin_systick(st10);
    for(int s = 0;s<10;++s){
        begin_systick(st0);
        busy_wait_ms(1000);
        end_systick(st0);
        print_systick(st0);
    }
    printf("For 10 loops:\n");
    end_systick(st10);
    print_systick(st10);

    free_systick(st10);
    free_systick(st0);
}

void demo_systick_list(){
    init_systick_reg();

    systick_count_t* st0 = (systick_count_t*) malloc(sizeof(systick_count_t));
    init_systick(st0);
    begin_systick(st0);

    systick_count_t* st1 = (systick_count_t*) malloc(sizeof(systick_count_t));
    init_systick(st1);
    begin_systick(st1);

    systick_count_t* st2 = (systick_count_t*) malloc(sizeof(systick_count_t));
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