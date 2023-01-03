#ifndef NTT_D_H
#define NTT_D_H

#include <stdint.h>
#include "pq/dilithium_params.h"

//#define ntt_D DILITHIUM_NAMESPACE(ntt_D)
void ntt_D(int32_t a[N_D]);

//#define invntt_tomont DILITHIUM_NAMESPACE(invntt_tomont)
void invntt_tomont(int32_t a[N_D]);

#endif
