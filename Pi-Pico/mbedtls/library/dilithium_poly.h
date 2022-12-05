#ifndef POL_DY_D_H
#define POL_DY_D_H

#include <stdint.h>
#include "pq/dilithium_params.h"

typedef struct {
  int32_t coeffs[N_D];
} poly;

//#define poly_reduce DIL_DITHIUM_NAMESPACE(poly_reduce)
void poly_reduce(poly *a);
//#define poly_caddq DIL_DITHIUM_NAMESPACE(poly_caddq)
void poly_caddq(poly *a);

//#define poly_add DIL_DITHIUM_NAMESPACE(poly_add)
void poly_add(poly *c, const poly *a, const poly *b);
//#define poly_sub DIL_DITHIUM_NAMESPACE(poly_sub)
void poly_sub(poly *c, const poly *a, const poly *b);
//#define poly_shiftl DIL_DITHIUM_NAMESPACE(poly_shiftl)
void poly_shiftl(poly *a);

//#define poly_ntt DIL_DITHIUM_NAMESPACE(poly_ntt)
void poly_ntt(poly *a);
//#define poly_invntt_tomont DIL_DITHIUM_NAMESPACE(poly_invntt_tomont)
void poly_invntt_tomont(poly *a);
//#define poly_pointwise_montgomery DIL_DITHIUM_NAMESPACE(poly_pointwise_montgomery)
void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b);

//#define poly_power2round DIL_DITHIUM_NAMESPACE(poly_power2round)
void poly_power2round(poly *a1, poly *a0, const poly *a);
//#define poly_decompose DIL_DITHIUM_NAMESPACE(poly_decompose)
void poly_decompose(poly *a1, poly *a0, const poly *a);
//#define poly_make_hint DIL_DITHIUM_NAMESPACE(poly_make_hint)
unsigned int poly_make_hint(poly *h, const poly *a0, const poly *a1);
//#define poly_use_hint DIL_DITHIUM_NAMESPACE(poly_use_hint)
void poly_use_hint(poly *b, const poly *a, const poly *h);

//#define poly_chknorm DIL_DITHIUM_NAMESPACE(poly_chknorm)
int poly_chknorm(const poly *a, int32_t B);
//#define poly_uniform DIL_DITHIUM_NAMESPACE(poly_uniform)
void poly_uniform(poly *a,
                  const unsigned char seed[SEEDBYTES_D],
                  uint16_t nonce);
//#define poly_uniform_eta DIL_DITHIUM_NAMESPACE(poly_uniform_eta)
void poly_uniform_eta(poly *a,
                      const unsigned char seed[CRHBYTES],
                      uint16_t nonce);
//#define poly_uniform_gamma1 DIL_DITHIUM_NAMESPACE(poly_uniform_gamma1)
void poly_uniform_gamma1(poly *a,
                         const unsigned char seed[CRHBYTES],
                         uint16_t nonce);
//#define poly_challenge DIL_DITHIUM_NAMESPACE(poly_challenge)
void poly_challenge(poly *c, const unsigned char seed[SEEDBYTES_D]);

//#define polyeta_pack DIL_DITHIUM_NAMESPACE(polyeta_pack)
void polyeta_pack(unsigned char *r, const poly *a);
//#define polyeta_unpack DIL_DITHIUM_NAMESPACE(polyeta_unpack)
void polyeta_unpack(poly *r, const unsigned char *a);

//#define polyt1_pack DIL_DITHIUM_NAMESPACE(polyt1_pack)
void polyt1_pack(unsigned char *r, const poly *a);
//#define polyt1_unpack DIL_DITHIUM_NAMESPACE(polyt1_unpack)
void polyt1_unpack(poly *r, const unsigned char *a);

//#define polyt0_pack DIL_DITHIUM_NAMESPACE(polyt0_pack)
void polyt0_pack(unsigned char *r, const poly *a);
//#define polyt0_unpack DIL_DITHIUM_NAMESPACE(polyt0_unpack)
void polyt0_unpack(poly *r, const unsigned char *a);

//#define polyz_pack DIL_DITHIUM_NAMESPACE(polyz_pack)
void polyz_pack(unsigned char *r, const poly *a);
//#define polyz_unpack DIL_DITHIUM_NAMESPACE(polyz_unpack)
void polyz_unpack(poly *r, const unsigned char *a);

//#define polyw1_pack DIL_DITHIUM_NAMESPACE(polyw1_pack)
void polyw1_pack(unsigned char *r, const poly *a);

#endif
