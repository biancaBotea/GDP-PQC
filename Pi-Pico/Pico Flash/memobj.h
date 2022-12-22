#include <stdio.h>
#include <stdlib.h>

typedef struct memobj{
    uint8_t* obj;
    size_t size_obj;
} memobj_t;

void init_memobj(memobj_t* mem, uint8_t* obj, size_t size_obj){
    mem->obj = obj;
    mem->size_obj = size_obj;
}

void print_memobj(memobj_t* mem){
    printf("Object stored at %p, %zu Bytes\n",mem->obj,mem->size_obj);
}

void free_memobj(memobj_t* mem){
    free(mem->obj);
    free(mem);
}

void demo_memobj(){
    char c = 'a';
    uint8_t* cp = (uint8_t*) &c;

    int i = 3;
    uint8_t* ip = (uint8_t*) &i;

    double d = 8.2;
    uint8_t* dp = (uint8_t*) &d;

    size_t size_cert = 128;
    uint8_t* cert = (uint8_t*) malloc(size_cert * sizeof(uint8_t));
    for(size_t i = 0; i<size_cert; ++i){
        cert[i] = rand() >> 23;
    }
    
    memobj_t* mc = (memobj_t*) malloc(sizeof(memobj_t));
    memobj_t* mi = (memobj_t*) malloc(sizeof(memobj_t));
    memobj_t* md = (memobj_t*) malloc(sizeof(memobj_t));
    memobj_t* mcert = (memobj_t*) malloc(sizeof(memobj_t));

    init_memobj(mc, cp, sizeof(c));
    init_memobj(mi, ip, sizeof(i));
    init_memobj(md, dp, sizeof(d));
    init_memobj(mcert,cert,size_cert);

    print_memobj(mc);
    print_memobj(mi);
    print_memobj(md);
    print_memobj(mcert);
    printf("done");
}