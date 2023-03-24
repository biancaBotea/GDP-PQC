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

void init_flashobj(flashobj_t* fo, uint8_t* mem, size_t size_mem);
void free_flashobj(flashobj_t* fo);

typedef struct flash{
    uint32_t sp_page;
    uint32_t sp_sector;
    size_t size_index;
    flashobj_t** index;
} flash_t;

void init_flash(flash_t* fl);
void free_mem_flash(flashobj_t* fo);
int write_obj_flash(flash_t* fl, flashobj_t* fo);
int read_obj_flash(flash_t* fl, size_t index);
void free_flash(flash_t* fl);
void demo_flash();
int demo_flasharray();