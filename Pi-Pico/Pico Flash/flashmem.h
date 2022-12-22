#include "flashobj.h"
#include "pico/stdlib.h"
#include "hardware/flash.h"
#include <math.h>

typedef struct flash{
    uint32_t sp_page;
    uint32_t sp_sector;
    size_t size_index;
    flashobj_t** index;
} flash_t;

void init_flash(flash_t* fl){
    //init page pointer to top of memory until first write enters page
    fl->sp_page = PICO_FLASH_SIZE_BYTES;
    //init sector pointer to top of memory until first write enters sector
    fl->sp_sector = PICO_FLASH_SIZE_BYTES;
    fl->size_index = 0;
    fl->index = NULL;
}

static void __prepare_new_sector_flash(flash_t* fl, flashobj_t* fo){
    uint32_t new_sp_page = fl->sp_page - fo->pages * FLASH_PAGE_SIZE;
    uint32_t new_bytes = fl->sp_sector - new_sp_page;
    //find number of new sectors
    size_t sectors = 1 + (new_bytes >> 12);
    //update sector pointer and erase sector by number of bytes
    size_t sector_bytes = FLASH_SECTOR_SIZE * sectors;
    fl->sp_sector -= sector_bytes;
    flash_range_erase(fl->sp_sector,sector_bytes);
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

    //update page stack pointer and program flash from buffer
    fl->sp_page = fl->sp_page - FLASH_PAGE_SIZE * fo->pages;
    flash_range_program(fl->sp_page,data,data_bytes);

    //verify flash from memory
    fo->flash_target = (uint8_t*) XIP_BASE + fl->sp_page;
    printf("Writing to flash at %p, %zu Bytes\n",fo->flash_target,fo->bytes);

    printf("Verifying flash memory, first 10b:\n");
    for(size_t b = 0; b < data_bytes; ++b){
        if(data[b] != fo->flash_target[b]){
            printf("Error: flash mismatch in page at %p byte %zu",fl->sp_page,b);
            return -1;
        }
        if(b<10){
            printf("%hu ",fo->flash_target[b]);
        }
        if(b==10){printf("\n");}
        
    }
    printf("Flash verify successful.\n");
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
    if((fl->sp_page + FLASH_PAGE_SIZE * fo->pages)>= fl->sp_sector){
        __prepare_new_sector_flash(fl,fo);
    }
    //write to cleared sector and verify
    if(__write_new_page_flash(fl,fo) != 0){
        return;
    }
    //once verified, may free memobject
    free_memobj(fo->mem);
    //add flash object to index
    if(__add_new_index_flash(fl,fo) != 0){
        return;
    }
}

void read_obj_flash(flash_t* fl, memobj_t* mem, size_t index){
    flashobj_t* fo = fl->index[index];
    printf("Reading from flash at %p, %zu Bytes\n",fo->flash_target,fo->bytes);
    mem->obj = (uint8_t*) malloc(fo->bytes * sizeof(uint8_t));
    for(size_t b = 0; b<fo->bytes; ++b){
        mem->obj[b] = fo->flash_target[b];
    }
    mem->size_obj = fo->bytes;
}

void free_flash(flash_t* fl){
    free(fl);
}

void demo_flash(){
    /*SETUP STAGE*/
    //Initialise flash structure
    flash_t* fl = (flash_t*) malloc(sizeof(flash_t));
    init_flash(fl);

    //Create test certificate object
    size_t size_cert = 10000;
    printf("Generating 10kb certificate; first 10b:\n");
    uint8_t* cert = (uint8_t*) malloc(size_cert * sizeof(uint8_t));
    for(size_t b = 0; b<size_cert; ++b){
        cert[b] = rand() >> 23;
        if(b<10){
            printf("%hu ",cert[b]);
        }
        else if(b==10){
            printf("\n");
        }
    }
    
    /*WRITE STAGE*/
    //Init memobj structure and print
    memobj_t * mc = (memobj_t*) malloc(sizeof(memobj_t));
    init_memobj(mc, cert, size_cert);
    print_memobj(mc);

    //Init flashobj structure
    flashobj_t* fo_cert = (flashobj_t*) malloc(sizeof(flashobj_t));
    init_flashobj(fo_cert, mc);

    //Write flashobj to flash
    printf("Writing to flash.\n");
    write_obj_flash(fl, fo_cert);
    print_memobj(mc);
    printf("\n\n\n");
    
    //Now verified, may free original memory
    // free(cert);

    /*READ STAGE*/
    //Read from flash at index 0 where flashobj should be indexed
    memobj_t* mc_flash = (memobj_t*) malloc(sizeof(memobj_t));
    read_obj_flash(fl,mc_flash,0);
    print_memobj(mc_flash);
    printf("Loaded memobject from flash, first 10b:\n");
    for(size_t b = 0; b<mc_flash->size_obj; ++b){
        if(b<10){
            printf("%hu ",mc_flash->obj[b]);
        }
        else if(b==10){
            printf("\n");
        }
    }

    // free_flashobj(fo_cert);
    // free_memobj(mc_flash);
    // free_flash(fl);
}