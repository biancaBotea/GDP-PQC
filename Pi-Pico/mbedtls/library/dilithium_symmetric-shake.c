#include <stdint.h>
#include "pq/dilithium_params.h"
#include "pq/dilithium_symmetric.h"
#include "fips202.h"

void dilithium_shake128_stream_init(keccak_state *state, const unsigned char seed[SEEDBYTES], uint16_t nonce)
{
  unsigned char t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake128_init(state);
  shake128_absorb(state, seed, SEEDBYTES);
  shake128_absorb(state, t, 2);
  shake128_finalize(state);
}

void dilithium_shake256_stream_init(keccak_state *state, const unsigned char seed[CRHBYTES], uint16_t nonce)
{
  unsigned char t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake256_init(state);
  shake256_absorb(state, seed, CRHBYTES);
  shake256_absorb(state, t, 2);
  shake256_finalize(state);
}
