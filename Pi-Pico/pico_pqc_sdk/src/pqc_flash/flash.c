#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include "pico/stdlib.h"
#include "hardware/flash.h"

typedef struct flashobj{
    uint8_t* mem;
    uint8_t* flash_target;
    size_t bytes;
    size_t pages;

    bool in_mem;
    bool in_flash;
} flashobj_t;

void init_flashobj(flashobj_t* fo, uint8_t* mem, size_t size_mem){
    fo->mem = mem;
    fo->bytes = size_mem;
    fo->pages = 1 + (fo->bytes >> 8);
    
    fo->flash_target = NULL;
    
    fo->in_mem = true;
    fo->in_flash = false;
}

void free_flashobj(flashobj_t* fo){
    free(fo->mem);
    free(fo);
}

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

void free_mem_flash(flashobj_t* fo){
    free(fo->mem);
    fo->in_mem = false;
}

static int __prepare_new_sector_flash(flash_t* fl, flashobj_t* fo){
    uint32_t new_sp_page = fl->sp_page - fo->pages * FLASH_PAGE_SIZE;
    uint32_t new_bytes = fl->sp_sector - new_sp_page;
    //find number of new sectors
    size_t sectors = 1 + (new_bytes >> 12);
    //update sector pointer and erase sector by number of bytes
    size_t sector_bytes = FLASH_SECTOR_SIZE * sectors;
    fl->sp_sector -= sector_bytes;
    flash_range_erase(fl->sp_sector,sector_bytes);
    uint8_t* sector_b = (uint8_t*) XIP_BASE + fl->sp_sector;
    for(int b = 0; b < sector_bytes; ++b){
        if(sector_b[b] != 0xFF){
            printf("Error, flash byte at %p !=0xFF, =%hu",sector_b+b,sector_b[b]);
            return -1;
        }
    }
    return 0;
}

static int __write_new_page_flash(flash_t* fl, flashobj_t* fo){
    //create buffer for data that is a multiple of page size 
    size_t data_bytes = FLASH_PAGE_SIZE * fo->pages; 
    uint8_t data[data_bytes];
    for(size_t b = 0; b < data_bytes; ++b){
        if(b < fo->bytes){
            data[b] = fo->mem[b];
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
    fo->in_flash = true;
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

int write_obj_flash(flash_t* fl, flashobj_t* fo){
    //check if writing in new sector
    //call to prepare (erase) new sector if needed
    if((fl->sp_page + FLASH_PAGE_SIZE * fo->pages)>= fl->sp_sector){
        if(__prepare_new_sector_flash(fl,fo) != 0){
            return -1;
        }
    }
    //write to cleared sector and verify
    if(__write_new_page_flash(fl,fo) != 0){
        return -2;
    }
    //add flash object to index
    if(__add_new_index_flash(fl,fo) != 0){
        return -3;
    }
    //once verified, may free memobject
    free_mem_flash(fo);
    return 0;
}

int read_obj_flash(flash_t* fl, size_t index){
    flashobj_t* fo = fl->index[index];
    if(fo->in_flash == true){

        if(fo->in_mem == false){
            printf("Reading from flash at %p, %zu Bytes\n",fo->flash_target,fo->bytes);
            fo->mem = (uint8_t*) malloc(fo->bytes * sizeof(uint8_t));
            if(fo->mem != NULL)
            {
                for(size_t b = 0; b<fo->bytes; ++b){
                    fo->mem[b] = fo->flash_target[b];
                }
            }
            else{
                printf("Could not allocate memory to load object from flash.\n");
                return -4;
            }
        }
        else{
            printf("Flash object already in memory; skipping load.\n");
            return -5;
        }
    }
    else{
        printf("Flash object not in flash; skipping load.\n");
        return -6;
    }
    return 0;
}

void free_flash(flash_t* fl){
    free(fl->index);
    free(fl);
}

void demo_flash(){
    /*SETUP STAGE*/
    //Initialise flash structure
    flash_t* fl = (flash_t*) malloc(sizeof(flash_t));
    init_flash(fl);

    //Create test certificate object
    size_t size_cert = 10000;
    uint8_t* cert = (uint8_t*) malloc(size_cert * sizeof(uint8_t));
    printf("Generating 10kb certificate to %p; first 10b:\n",cert);
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
    //Init flashobj structure
    flashobj_t* fo_cert = (flashobj_t*) malloc(sizeof(flashobj_t));
    init_flashobj(fo_cert,cert,size_cert);

    //Write flashobj to flash
    write_obj_flash(fl, fo_cert);
        
    //Check that object has been removed from memory
    /*READ STAGE*/
    //Read from flash at index 0 where flashobj should be indexed
    read_obj_flash(fl,0);
    printf("Loaded from flash to %p, first 10b:\n",fl->index[0]->mem);
    for(size_t b = 0; b<fo_cert->bytes; ++b){
        if(b<10){
            printf("%hu ",fl->index[0]->mem[b]);
        }
        else if(b==10){
            printf("\n\n");
        }
    }

    free_flashobj(fo_cert);
    free_flash(fl);
}

int demo_flasharray(){
    /*SETUP STAGE*/
    //Initialise flash structure
    flash_t* fl = (flash_t*) malloc(sizeof(flash_t));
    init_flash(fl);

    /*WRITE STAGE*/
    size_t num_certs = 3;
    for(size_t c = 0; c < num_certs; ++c){
        size_t size_cert = rand() >> 16;
        uint8_t* cert = (uint8_t*) malloc(size_cert * sizeof(uint8_t));
        printf("%zu: Generating %zub certificate to %p; first 10b:\n",c,size_cert,cert);
        for(size_t b = 0; b<size_cert; ++b){
            cert[b] = rand() >> 23;
            if(b<10){printf("%hu ",cert[b]);}
            else if(b==10){printf("\n");}
        }
        //Init flashobj structure
        flashobj_t* fo_cert = (flashobj_t*) malloc(sizeof(flashobj_t));
        init_flashobj(fo_cert,cert,size_cert);

        //Write flashobj to flash
        int ret;
        if(ret = write_obj_flash(fl, fo_cert) != 0){
            printf("%d",ret);
            return ret;
        }
        
        printf("\n");
    }

    /*READ STAGE*/
    //Read from flash at index 0 where flashobj should be indexed
    for(size_t c = 0; c < num_certs; ++c){
        size_t bytes = fl->index[c]->bytes;
        int ret;
        if(ret = read_obj_flash(fl,c) != 0){
            return ret;
        }
        
        printf("%zu: Loaded from flash to %p, first 10b:\n",c,fl->index[c]->mem);
        for(size_t b = 0; b<bytes; ++b){
            if(b<10){
                printf("%hu ",fl->index[c]->mem[b]);
            }
            else if(b==10){
                printf("\n\n");
            }
        }
    }
    free_flash(fl);
    return 0;
}