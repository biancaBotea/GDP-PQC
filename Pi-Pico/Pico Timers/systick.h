#include <stdio.h>
#include "pico/stdlib.h"
#include "hardware/exception.h"
#include "hardware/structs/systick.h"

typedef struct systick_count{
    uint32_t rvr_max;
    uint32_t csr_init;
    uint32_t csr_end;
    uint32_t countflag_sum;
    uint64_t csr_sum;
} systick_count_t;

systick_count_t c;

void get_systick(systick_hw_t* st){

    /*SYST_CSR - SysTick Control and Status Register*/
    //SysTick CSR Overflow Count Flag
    uint32_t CSR_COUNTFLAG = (st->csr & M0PLUS_SYST_CSR_BITS) >> M0PLUS_SYST_CSR_COUNTFLAG_LSB;

    /*SYST_CVR - SysTick Current Value Register*/
    //SysTick Value in CVR 0:23
    uint32_t CVR_CURRENT = (st->cvr & M0PLUS_SYST_CVR_CURRENT_BITS);

    printf("CSR_COUNTFLAG:%lu CVR_CURRENT:%lu\n",
        CSR_COUNTFLAG,
        CVR_CURRENT);
}

void init_systick(systick_hw_t* st, exception_handler_t (*st_ex)(void)){
    exception_set_exclusive_handler(SYSTICK_EXCEPTION, st_ex);
    
    /*SYST_RVR - SysTick Reload Value Register*/
    //SysTick Reload Value to Max = 0x00FFFFFF
    uint32_t SYSTICK_MAX = 0xFFFFFF;
    c.rvr_max = SYSTICK_MAX;
    st->rvr &= M0PLUS_SYST_RVR_BITS & SYSTICK_MAX;
    
    /*SYST_CVR - SysTick Current Value Register*/
    //SysTick Clear Current Value, write a value to clear CVR_CURRENT and CSR_COUNTFLAG
    st->cvr &= M0PLUS_SYST_CVR_CURRENT_BITS & 0;

    /*SYST_CSR - SysTick Control and Status Register*/
    //SysTick Exception Request on Counter Zero = 1
    st->csr |= M0PLUS_SYST_CSR_TICKINT_BITS;

    //Processor Clock Source for SysTick = 1
    st->csr |= M0PLUS_SYST_CSR_CLKSOURCE_BITS;
}


void begin_systick(systick_hw_t* st){
    //Enable Counter
    st->csr |= M0PLUS_SYST_CSR_ENABLE_BITS;
    c.csr_init = c.rvr_max;
}

void end_systick(systick_hw_t* st){
    //Disable Counter
    st->csr &= ~M0PLUS_SYST_CSR_ENABLE_BITS;

    c.csr_end = (st->cvr & M0PLUS_SYST_CVR_CURRENT_BITS);
    
    c.csr_sum = (2+c.countflag_sum)*c.rvr_max - c.csr_init - c.csr_end;
    printf("Clock Cycles:%llu\n\n", c.csr_sum);

    //Reset Counter
    st->cvr &= M0PLUS_SYST_CVR_CURRENT_BITS & 0;
    //Reset Counter Stats
    c.csr_init = 0;
    c.csr_end = 0;
    c.countflag_sum = 0;
}

exception_handler_t handle_systick(){
    c.countflag_sum += 1;
}

void sleep_time(int time_s){
    uint32_t time_enter_sleep = time_us_32();
    sleep_ms(1000 * time_s);
    uint32_t time_leave_sleep = time_us_32();
    uint32_t time_diff_sleep = time_leave_sleep - time_enter_sleep;
    printf("Entered sleep at: %lu\nLeft sleep at: %lu\nSleep time: %lu\n", \
        time_enter_sleep, \
        time_leave_sleep, \
        time_diff_sleep);
}