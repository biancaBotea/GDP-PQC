
#include <sys/stat.h>
#include <string.h>
#include <malloc.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

//Latency measuring (cut: codes under test)
clock_t start_cut = clock();
//----------------------------
//
//  CUT: codes under test
//
//--------------------------
clock_t diff_cut = clock() - start_cut;
double diff_cut_value = (double)diff_cut / ((double)CLOCKS_PER_SEC / 1000.0);
printf("Code under test executed in % fms \n", (float)diff_cut_value);


//Memory usage measuring
//Function defination
long get_stack_usage(){
    struct rusage r_usage;
    getrusage(RUSAGE_SELF, &r_usage);
    return r_usage.ru_maxrss;
}

long stack_usage_before = get_stack_usage();
struct mallinfo mem_info_before = mallinfo();
//----------------------------
//
//  CUT: codes under test
//
//----------------------------
long stack_usage_after = get_stack_usage();
struct mallinfo mem_info_after = mallinfo();

printf("\nHeap usage difference: %ld\n", mem_info_after.uordblks - mem_info_before.uordblks);
printf("\nStack usage difference: %ld\n", stack_usage_after - stack_usage_before);
