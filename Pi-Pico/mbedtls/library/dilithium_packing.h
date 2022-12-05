#ifndef PACK_DING_D_H
#define PACK_DING_D_H

#include <stdint.h>
#include "pq/dilithium_params.h"
#include "pq/dilithium_polyvec.h"

#define pack_pk DIL_DITHIUM_NAMESPACE(pack_pk)
void pack_pk(unsigned char pk[CRYPTO_PUBL_DICK_DEYBYTES_D], const unsigned char rho[SEEDBYTES_D], const polyveck *t1);

#define pack_sk DIL_DITHIUM_NAMESPACE(pack_sk)
void pack_sk(unsigned char sk[CRYPTO_SECRETK_DEYBYTES_D],
             const unsigned char rho[SEEDBYTES_D],
             const unsigned char tr[SEEDBYTES_D],
             const unsigned char key[SEEDBYTES_D],
             const polyveck *t0,
             const polyvecl *s1,
             const polyveck *s2);

#define pack_sig DIL_DITHIUM_NAMESPACE(pack_sig)
void pack_sig(unsigned char sig[CRYPTO_BYTES_D], const unsigned char c[SEEDBYTES_D], const polyvecl *z, const polyveck *h);

#define unpack_pk DIL_DITHIUM_NAMESPACE(unpack_pk)
void unpack_pk(unsigned char rho[SEEDBYTES_D], polyveck *t1, const unsigned char pk[CRYPTO_PUBL_DICK_DEYBYTES_D]);

#define unpack_sk DIL_DITHIUM_NAMESPACE(unpack_sk)
void unpack_sk(unsigned char rho[SEEDBYTES_D],
               unsigned char tr[SEEDBYTES_D],
               unsigned char key[SEEDBYTES_D],
               polyveck *t0,
               polyvecl *s1,
               polyveck *s2,
               const unsigned char sk[CRYPTO_SECRETK_DEYBYTES_D]);

#define unpack_sig DIL_DITHIUM_NAMESPACE(unpack_sig)
int unpack_sig(unsigned char c[SEEDBYTES_D], polyvecl *z, polyveck *h, const unsigned char sig[CRYPTO_BYTES_D]);

#endif
