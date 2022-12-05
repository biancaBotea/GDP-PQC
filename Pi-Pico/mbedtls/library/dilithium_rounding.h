#ifndef ROUNDING_D_H
#define ROUNDING_D_H

#include <stdint.h>
#include "pq/dilithium_params.h"

// #define power2round DIL_DITHIUM_NAMESPACE(power2round)
int32_t power2round(int32_t *a0, int32_t a);

// #define decompose DIL_DITHIUM_NAMESPACE(decompose)
int32_t decompose(int32_t *a0, int32_t a);

// #define make_hint DIL_DITHIUM_NAMESPACE(make_hint)
unsigned int make_hint(int32_t a0, int32_t a1);

// #define use_hint DIL_DITHIUM_NAMESPACE(use_hint)
int32_t use_hint(int32_t a, unsigned int hint);

#endif
