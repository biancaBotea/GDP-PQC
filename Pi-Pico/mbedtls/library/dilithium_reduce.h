#ifndef REDUCE_D_H
#define REDUCE_D_H

#include <stdint.h>
#include "pq/dilithium_params.h"

#define MONT -4186625 // 2^32 % Q_D
#define QINV 58728449 // q^(-1) mod 2^32

// #define montgomery_reduce DIL_DITHIUM_NAMESPACE(montgomery_reduce)
int32_t montgomery_reduce(int64_t a);

// #define reduce32 DIL_DITHIUM_NAMESPACE(reduce32)
int32_t reduce32(int32_t a);

// #define caddq DIL_DITHIUM_NAMESPACE(caddq)
int32_t caddq(int32_t a);

// #define freeze DIL_DITHIUM_NAMESPACE(freeze)
int32_t freeze(int32_t a);

#endif
