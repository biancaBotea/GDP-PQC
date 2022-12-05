#ifndef FIPS202_H
#define FIPS202_H

#include <stddef.h>
#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

#define FIPS202_NAMESPACE(s) pqcrystals_dilithium_fips202_ref_##s

typedef struct {
  uint64_t s[25];
  unsigned int pos;
} keccak_state;

#define KeccakF_RoundConstants FIPS202_NAMESPACE(KeccakF_RoundConstants)
extern const uint64_t KeccakF_RoundConstants[];

//#define shake128_init_d FIPS202_NAMESPACE(shake128_init_d)
void shake128_init_d(keccak_state *state);
//#define shake128_absorb_d FIPS202_NAMESPACE(shake128_absorb_d)
void shake128_absorb_d(keccak_state *state, const uint8_t *in, size_t inlen);
//#define shake128_finalize_d FIPS202_NAMESPACE(shake128_finalize_d)
void shake128_finalize_d(keccak_state *state);
//#define shake128_squeeze_d FIPS202_NAMESPACE(shake128_squeeze_d)
void shake128_squeeze_d(uint8_t *out, size_t outlen, keccak_state *state);
//#define shake128_absorb_once_d FIPS202_NAMESPACE(shake128_absorb_once_d)
void shake128_absorb_once_d(keccak_state *state, const uint8_t *in, size_t inlen);
//#define shake128_squeezeblocks_d FIPS202_NAMESPACE(shake128_squeezeblocks_d)
void shake128_squeezeblocks_d(uint8_t *out, size_t nblocks, keccak_state *state);

//#define shake256_init_d FIPS202_NAMESPACE(shake256_init_d)
void shake256_init_d(keccak_state *state);
//#define shake256_absorb_d FIPS202_NAMESPACE(shake256_absorb_d)
void shake256_absorb_d(keccak_state *state, const uint8_t *in, size_t inlen);
//#define shake256_finalize_d FIPS202_NAMESPACE(shake256_finalize_d)
void shake256_finalize_d(keccak_state *state);
//#define shake256_squeeze_d FIPS202_NAMESPACE(shake256_squeeze_d)
void shake256_squeeze_d(uint8_t *out, size_t outlen, keccak_state *state);
//#define shake256_absorb_once_d FIPS202_NAMESPACE(shake256_absorb_once_d)
void shake256_absorb_once_d(keccak_state *state, const uint8_t *in, size_t inlen);
//#define shake256_squeezeblocks_d FIPS202_NAMESPACE(shake256_squeezeblocks_d)
void shake256_squeezeblocks_d(uint8_t *out, size_t nblocks,  keccak_state *state);

//#define shake128_d FIPS202_NAMESPACE(shake128_d)
void shake128_d(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
//#define shake256_d FIPS202_NAMESPACE(shake256_d)
void shake256_d(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
//#define sha3_256_d FIPS202_NAMESPACE(sha3_256_d)
void sha3_256_d(uint8_t h[32], const uint8_t *in, size_t inlen);
//#define sha3_512_d FIPS202_NAMESPACE(sha3_512_d)
void sha3_512_d(uint8_t h[64], const uint8_t *in, size_t inlen);

#endif
