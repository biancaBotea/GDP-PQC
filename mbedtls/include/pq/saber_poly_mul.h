#ifndef SABER_POLY_MUL_H
#define SABER_POLY_MUL_H

#include "saber_params.h"
#include <stdint.h>

void poly_mul_acc(const uint16_t a[SABER_N], const uint16_t b[SABER_N], uint16_t res[SABER_N]);

#endif
