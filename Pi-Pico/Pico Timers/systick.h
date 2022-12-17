#include <stdio.h>
#include "pico/stdlib.h"
#include "hardware/exception.h"
#include "hardware/structs/systick.h"

typedef struct systick_count{
    systick_hw_t* st;    
    uint32_t rvr_max;
    uint32_t csr_init;
    uint32_t csr_end;
    uint32_t countflag_sum;
    uint64_t csr_sum;
} systick_count_t;

systick_count_t st_ct;

exception_handler_t handle_systick(){
    st_ct.countflag_sum += 1;
}

void init_systick(){
    st_ct.st = systick_hw;
    
    st_ct.rvr_max = 0;
    st_ct.csr_init = 0;
    st_ct.csr_end = 0;
    st_ct.countflag_sum = 0;
    st_ct.csr_sum = 0;

    exception_handler_t (*st_h)(void) = &handle_systick;
    exception_set_exclusive_handler(SYSTICK_EXCEPTION, st_h);
    
    /*SYST_RVR - SysTick Reload Value Register*/
    //SysTick Reload Value to Max = 0x00FFFFFF
    uint32_t SYSTICK_MAX = 0xFFFFFF;
    st_ct.rvr_max = SYSTICK_MAX;
    st_ct.st->rvr &= M0PLUS_SYST_RVR_BITS & SYSTICK_MAX;
    
    /*SYST_CVR - SysTick Current Value Register*/
    //SysTick Clear Current Value, write a value to clear CVR_CURRENT and CSR_COUNTFLAG
    st_ct.st->cvr &= M0PLUS_SYST_CVR_CURRENT_BITS & 0;

    /*SYST_CSR - SysTick Control and Status Register*/
    //SysTick Exception Request on Counter Zero = 1
    st_ct.st->csr |= M0PLUS_SYST_CSR_TICKINT_BITS;

    //Processor Clock Source for SysTick = 1
    st_ct.st->csr |= M0PLUS_SYST_CSR_CLKSOURCE_BITS;

}


void begin_systick(){
    /*SYST_CSR - SysTick Control and Status Register*/
    //Enable Counter
    st_ct.st->csr |= M0PLUS_SYST_CSR_ENABLE_BITS;
    st_ct.csr_init = st_ct.rvr_max;
}

void end_systick(){
    /*SYST_CSR - SysTick Control and Status Register*/
    //Disable Counter
    st_ct.st->csr &= ~M0PLUS_SYST_CSR_ENABLE_BITS;

    st_ct.csr_end = (st_ct.st->cvr & M0PLUS_SYST_CVR_CURRENT_BITS);
    
    st_ct.csr_sum = (2+st_ct.countflag_sum)*st_ct.rvr_max - st_ct.csr_init - st_ct.csr_end;
    printf("Clock Cycles:%llu\n\n", st_ct.csr_sum);

    /*SYST_CVR - SysTick Current Value Register*/
    //Reset Counter
    st_ct.st->cvr &= M0PLUS_SYST_CVR_CURRENT_BITS & 0;
    //Reset Counter Stats
    st_ct.csr_init = 0;
    st_ct.csr_end = 0;
    st_ct.countflag_sum = 0;
}

void get_systick(){

    /*SYST_CSR - SysTick Control and Status Register*/
    //SysTick CSR Overflow Count Flag
    uint32_t CSR_COUNTFLAG = (st_ct.st->csr & M0PLUS_SYST_CSR_BITS) >> M0PLUS_SYST_CSR_COUNTFLAG_LSB;

    /*SYST_CVR - SysTick Current Value Register*/
    //SysTick Value in CVR 0:23
    uint32_t CVR_CURRENT = (st_ct.st->cvr & M0PLUS_SYST_CVR_CURRENT_BITS);

    printf("CSR_COUNTFLAG:%lu CVR_CURRENT:%lu\n",
        CSR_COUNTFLAG,
        CVR_CURRENT);
}