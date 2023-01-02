#include <stdint.h>
#include "pq/dilithium_params.h"
#include "pq/dilithium_symmetric.h"
#include "pq/dilithium_fips202.h"

void dilithium_shake128_stream_init(keccak_state *state, const unsigned char seed[SEEDBYTES_D], uint16_t nonce)
{
  unsigned char t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake128_init_d(state);
  shake128_absorb_d(state, seed, SEEDBYTES_D);
  shake128_absorb_d(state, t, 2);
  shake128_finalize_d(state);
}

void dilithium_shake256_stream_init(keccak_state *state, const unsigned char seed[CRHBYTES], uint16_t nonce)
{
  unsigned char t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake256_init_d(state);
  shake256_absorb_d(state, seed, CRHBYTES);
  shake256_absorb_d(state, t, 2);
  shake256_finalize_d(state);
}
