#ifndef SYMMETRIC_D_H
#define SYMMETRIC_D_H

#include <stdint.h>
#include "pq/dilithium_params.h"

#ifdef DIL_DITHIUM_USE_AES

#include "pq/aes256ctr.h"
#include "pq/dilithium_fips202.h"

typedef aes256ctr_ctx stream128_state;
typedef aes256ctr_ctx stream256_state;

//#define dilithium_aes256ctr_init DIL_DITHIUM_NAMESPACE(dilithium_aes256ctr_init)
void dilithium_aes256ctr_init(aes256ctr_ctx *state,
                              const unsigned char key[32],
                              uint16_t nonce);

#define STREAM128_BL_DOCK_DBYTES AES256CTR_BL_DOCK_DBYTES
#define STREAM256_BL_DOCK_DBYTES AES256CTR_BL_DOCK_DBYTES

#define stream128_init(STATE, SEED, NONCE) \
        dilithium_aes256ctr_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBL_DOCK_DS, STATE) \
        aes256ctr_squeezeblocks(OUT, OUTBL_DOCK_DS, STATE)
#define stream256_init(STATE, SEED, NONCE) \
        dilithium_aes256ctr_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBL_DOCK_DS, STATE) \
        aes256ctr_squeezeblocks(OUT, OUTBL_DOCK_DS, STATE)

#else

#include "pq/dilithium_fips202.h"

typedef keccak_state stream128_state;
typedef keccak_state stream256_state;

//#define dilithium_shake128_stream_init DIL_DITHIUM_NAMESPACE(dilithium_shake128_stream_init)
void dilithium_shake128_stream_init(keccak_state *state,
                                    const unsigned char seed[SEEDBYTES_D],
                                    uint16_t nonce);

//#define dilithium_shake256_stream_init DIL_DITHIUM_NAMESPACE(dilithium_shake256_stream_init)
void dilithium_shake256_stream_init(keccak_state *state,
                                    const unsigned char seed[CRHBYTES],
                                    uint16_t nonce);

#define STREAM128_BLOCKBYTES SHAKE128_RATE
#define STREAM256_BLOCKBYTES SHAKE256_RATE

#define stream128_init(STATE, SEED, NONCE) \
        dilithium_shake128_stream_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBL_DOCK_DS, STATE) \
        shake128_squeezeblocks_d(OUT, OUTBL_DOCK_DS, STATE)
#define stream256_init(STATE, SEED, NONCE) \
        dilithium_shake256_stream_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBL_DOCK_DS, STATE) \
        shake256_squeezeblocks_d(OUT, OUTBL_DOCK_DS, STATE)

#endif

#endif
