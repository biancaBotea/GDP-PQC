#include "memobj.h"

typedef struct flashobj{
    memobj_t* mem;
    
    uint8_t* flash_target;
    size_t bytes;
    size_t pages;

} flashobj_t;

void init_flashobj(flashobj_t* fo, memobj_t* mem){
    fo->mem = mem;
    fo->flash_target = NULL;
    fo->bytes = mem->size_obj;

    fo->pages = 1 + (fo->bytes >> 8);
}

void free_flashobj(flashobj_t* fo){
    free(fo->mem);
    free(fo);
}