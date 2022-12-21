#include "memobj.h"

typedef struct flashobj{
    memobj_t* mem;
    
    uint8_t* obj;
    size_t byte_start;
    size_t bytes;

    uint8_t* page;
    size_t page_start;
    size_t pages;

    uint8_t* sector;
    size_t sector_start;
    size_t sectors;
} flashobj_t;

void init_flashobj(flashobj_t* fo, memobj_t* mem){
    fo->mem = mem;
    fo->obj = NULL;
    fo->byte_start = 0;
    fo->bytes = mem->size_obj;

    fo->page = NULL;
    fo->page_start = 0;
    fo->pages = round((float) fo->bytes / (float) FLASH_PAGE_SIZE);

    fo->sector = NULL;
    fo->sector_start = 0;
    fo->sectors = 0;
}

void free_flashobj(flashobj_t* fo){
    free(fo->mem);
    free(fo->obj);
    free(fo->page);
    free(fo->sector);
    free(fo);
}