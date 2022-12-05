#include "params.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"

/*************************************************
* Name:        pack_pk
*
* Description: Bit-pack public key pk = (rho, t1).
*
* Arguments:   - uint8_t pk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const polyveck *t1: pointer to vector t1
**************************************************/
void pack_pk(uint8_t pk[CRYPTO_PUBL_DICK_DEYBYTES_D],
             const uint8_t rho[SEEDBYTES_D],
             const polyveck *t1)
{
  unsigned int i;

  for(i = 0; i < SEEDBYTES_D; ++i)
    pk[i] = rho[i];
  pk += SEEDBYTES_D;

  for(i = 0; i < K_D; ++i)
    polyt1_pack(pk + i*POL_DYT1_PACK_DEDBYTES, &t1->vec[i]);
}

/*************************************************
* Name:        unpack_pk
*
* Description: Unpack public key pk = (rho, t1).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const polyveck *t1: pointer to output vector t1
*              - uint8_t pk[]: byte array containing bit-packed pk
**************************************************/
void unpack_pk(uint8_t rho[SEEDBYTES_D],
               polyveck *t1,
               const uint8_t pk[CRYPTO_PUBL_DICK_DEYBYTES_D])
{
  unsigned int i;

  for(i = 0; i < SEEDBYTES_D; ++i)
    rho[i] = pk[i];
  pk += SEEDBYTES_D;

  for(i = 0; i < K_D; ++i)
    polyt1_unpack(&t1->vec[i], pk + i*POL_DYT1_PACK_DEDBYTES);
}

/*************************************************
* Name:        pack_sk
*
* Description: Bit-pack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - uint8_t sk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const uint8_t tr[]: byte array containing tr
*              - const uint8_t key[]: byte array containing key
*              - const polyveck *t0: pointer to vector t0
*              - const polyvecl *s1: pointer to vector s1
*              - const polyveck *s2: pointer to vector s2
**************************************************/
void pack_sk(uint8_t sk[CRYPTO_SECRETK_DEYBYTES_D],
             const uint8_t rho[SEEDBYTES_D],
             const uint8_t tr[SEEDBYTES_D],
             const uint8_t key[SEEDBYTES_D],
             const polyveck *t0,
             const polyvecl *s1,
             const polyveck *s2)
{
  unsigned int i;

  for(i = 0; i < SEEDBYTES_D; ++i)
    sk[i] = rho[i];
  sk += SEEDBYTES_D;

  for(i = 0; i < SEEDBYTES_D; ++i)
    sk[i] = key[i];
  sk += SEEDBYTES_D;

  for(i = 0; i < SEEDBYTES_D; ++i)
    sk[i] = tr[i];
  sk += SEEDBYTES_D;

  for(i = 0; i < L_D; ++i)
    polyeta_pack(sk + i*POL_DYETA_PACK_DEDBYTES, &s1->vec[i]);
  sk += L_D*POL_DYETA_PACK_DEDBYTES;

  for(i = 0; i < K_D; ++i)
    polyeta_pack(sk + i*POL_DYETA_PACK_DEDBYTES, &s2->vec[i]);
  sk += K_D*POL_DYETA_PACK_DEDBYTES;

  for(i = 0; i < K_D; ++i)
    polyt0_pack(sk + i*POL_DYT0_PACK_DEDBYTES, &t0->vec[i]);
}

/*************************************************
* Name:        unpack_sk
*
* Description: Unpack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const uint8_t tr[]: output byte array for tr
*              - const uint8_t key[]: output byte array for key
*              - const polyveck *t0: pointer to output vector t0
*              - const polyvecl *s1: pointer to output vector s1
*              - const polyveck *s2: pointer to output vector s2
*              - uint8_t sk[]: byte array containing bit-packed sk
**************************************************/
void unpack_sk(uint8_t rho[SEEDBYTES_D],
               uint8_t tr[SEEDBYTES_D],
               uint8_t key[SEEDBYTES_D],
               polyveck *t0,
               polyvecl *s1,
               polyveck *s2,
               const uint8_t sk[CRYPTO_SECRETK_DEYBYTES_D])
{
  unsigned int i;

  for(i = 0; i < SEEDBYTES_D; ++i)
    rho[i] = sk[i];
  sk += SEEDBYTES_D;

  for(i = 0; i < SEEDBYTES_D; ++i)
    key[i] = sk[i];
  sk += SEEDBYTES_D;

  for(i = 0; i < SEEDBYTES_D; ++i)
    tr[i] = sk[i];
  sk += SEEDBYTES_D;

  for(i=0; i < L_D; ++i)
    polyeta_unpack(&s1->vec[i], sk + i*POL_DYETA_PACK_DEDBYTES);
  sk += L_D*POL_DYETA_PACK_DEDBYTES;

  for(i=0; i < K_D; ++i)
    polyeta_unpack(&s2->vec[i], sk + i*POL_DYETA_PACK_DEDBYTES);
  sk += K_D*POL_DYETA_PACK_DEDBYTES;

  for(i=0; i < K_D; ++i)
    polyt0_unpack(&t0->vec[i], sk + i*POL_DYT0_PACK_DEDBYTES);
}

/*************************************************
* Name:        pack_sig
*
* Description: Bit-pack signature sig = (c, z, h).
*
* Arguments:   - uint8_t sig[]: output byte array
*              - const uint8_t *c: pointer to challenge hash length SEEDBYTES_D
*              - const polyvecl *z: pointer to vector z
*              - const polyveck *h: pointer to hint vector h
**************************************************/
void pack_sig(uint8_t sig[CRYPTO_BYTES_D],
              const uint8_t c[SEEDBYTES_D],
              const polyvecl *z,
              const polyveck *h)
{
  unsigned int i, j, k;

  for(i=0; i < SEEDBYTES_D; ++i)
    sig[i] = c[i];
  sig += SEEDBYTES_D;

  for(i = 0; i < L_D; ++i)
    polyz_pack(sig + i*POL_DYZ_PACK_DEDBYTES, &z->vec[i]);
  sig += L_D*POL_DYZ_PACK_DEDBYTES;

  /* Encode h */
  for(i = 0; i < OMEGA + K_D; ++i)
    sig[i] = 0;

  k = 0;
  for(i = 0; i < K_D; ++i) {
    for(j = 0; j < N_D; ++j)
      if(h->vec[i].coeffs[j] != 0)
        sig[k++] = j;

    sig[OMEGA + i] = k;
  }
}

/*************************************************
* Name:        unpack_sig
*
* Description: Unpack signature sig = (c, z, h).
*
* Arguments:   - uint8_t *c: pointer to output challenge hash
*              - polyvecl *z: pointer to output vector z
*              - polyveck *h: pointer to output hint vector h
*              - const uint8_t sig[]: byte array containing
*                bit-packed signature
*
* Returns 1 in case of malformed signature; otherwise 0.
**************************************************/
int unpack_sig(uint8_t c[SEEDBYTES_D],
               polyvecl *z,
               polyveck *h,
               const uint8_t sig[CRYPTO_BYTES_D])
{
  unsigned int i, j, k;

  for(i = 0; i < SEEDBYTES_D; ++i)
    c[i] = sig[i];
  sig += SEEDBYTES_D;

  for(i = 0; i < L_D; ++i)
    polyz_unpack(&z->vec[i], sig + i*POL_DYZ_PACK_DEDBYTES);
  sig += L_D*POL_DYZ_PACK_DEDBYTES;

  /* Decode h */
  k = 0;
  for(i = 0; i < K_D; ++i) {
    for(j = 0; j < N_D; ++j)
      h->vec[i].coeffs[j] = 0;

    if(sig[OMEGA + i] < k || sig[OMEGA + i] > OMEGA)
      return 1;

    for(j = k; j < sig[OMEGA + i]; ++j) {
      /* Coefficients are ordered for strong unforgeability */
      if(j > k && sig[j] <= sig[j-1]) return 1;
      h->vec[i].coeffs[sig[j]] = 1;
    }

    k = sig[OMEGA + i];
  }

  /* Extra indices are zero for strong unforgeability */
  for(j = k; j < OMEGA; ++j)
    if(sig[j])
      return 1;

  return 0;
}
