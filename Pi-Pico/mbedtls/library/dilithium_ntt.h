#ifndef NTT_D_H
#define NTT_D_H

#include <stdint.h>
#include "pq/dilithium_params.h"

#define ntt DIL_DITHIUM_NAMESPACE(ntt)
void ntt(int32_t a[N_D]);

#define invntt_tomont DIL_DITHIUM_NAMESPACE(invntt_tomont)
void invntt_tomont(int32_t a[N_D]);

#endif
