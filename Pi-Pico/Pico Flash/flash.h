#include <stdio.h>
#include <math.h>
#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "flashobj.h"

typedef struct flash{
    uint32_t sp_page;
    uint32_t sp_sector;
    size_t size_index;
    flashobj_t** index;
} flash_t;

void init_flash(flash_t* fl){
    fl->sp_page = XIP_BASE + PICO_FLASH_SIZE_BYTES - FLASH_PAGE_SIZE;
    fl->sp_sector = XIP_BASE + PICO_FLASH_SIZE_BYTES - FLASH_SECTOR_SIZE;
    fl->size_index = 0;
    fl->index = NULL;
}

static void __prepare_new_sector_flash(flash_t* fl, flashobj_t* fo){
    //find number of new sectors
    size_t sectors = round((float) ((&fl->sp_page + fo->pages) - &fl->sp_sector)/(float) FLASH_SECTOR_SIZE);
    //erase sectors
    flash_range_erase(fl->sp_sector,FLASH_SECTOR_SIZE * sectors);
    //assign sectors, sector pointer, and new stack pointer for sector.
    fo->sectors = sectors;
    fo->sector_start = fl->sp_sector;
    fl->sp_sector = fl->sp_sector + FLASH_SECTOR_SIZE * sectors;
}

static int __write_new_page_flash(flash_t* fl, flashobj_t* fo){
    //create buffer for data that is a multiple of page size 
    size_t data_bytes = FLASH_PAGE_SIZE * fo->pages; 
    uint8_t data[data_bytes];
    for(size_t b = 0; b < data_bytes; ++b){
        if(b < fo->bytes){
            data[b] = fo->mem->obj[b];
        }
        else{
            data[b] = 0;
        }
    }
    //program flash from page buffer
    flash_range_program(fl->sp_page,data,data_bytes);
    //verify flash from memory
    const uint8_t *flash_target_read = (const uint8_t*) fl->sp_page;
    for(size_t b = 0; b < data_bytes; ++b){
        if(data[b] != flash_target_read[b]){
            printf("Error: flash mismatch in page at %p byte %zu",fl->sp_page,b);
            return -1;
        }
    }
    //assign page pointer, update stack pointer for sector.
    fo->page_start = fl->sp_page;
    fl->sp_page = fl->sp_page + FLASH_PAGE_SIZE * fo->pages;
    return 0;
}

static int __add_new_index_flash(flash_t* fl, flashobj_t* fo){
    //temporary new size, new head, and index pointer
    size_t temp_size_index = fl->size_index + 1;
    size_t head_size_index = temp_size_index - 1;
    flashobj_t** temp_index = (flashobj_t**) realloc(fl->index, temp_size_index * sizeof(flashobj_t*));
    if(temp_index != NULL){
        //if successful realloc, assign new flash object to head and return 0.
        fl->index = temp_index;
        fl->index[head_size_index] = fo;
        fl->size_index +=1;
        return 0;
    }
    else{
        //else, print error and return -1. 
        printf("Could not allocate memory for new flashobj in list.\n");
        return -1;
    }
}

void write_obj_flash(flash_t* fl, flashobj_t* fo){
    //check if writing in new sector
    //call to prepare (erase) new sector if needed
    if((&fl->sp_page + fo->pages)>= &fl->sp_sector){
        __prepare_new_sector_flash(fl,fo);
    }
    //write to cleared sector and verify
    if(__write_new_page_flash(fl,fo) != 0){
        return;
    }
    //add flash object to index
    if(__add_new_index_flash(fl,fo) != 0){
        return;
    }
}

void free_flash(flash_t* fl){
    free(fl);
}
