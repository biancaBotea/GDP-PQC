#include "pq/saber_params.h"
// #include <string.h>
// #include <stdint.h>
// #include <stdio.h>
#include "pq/saber_indcpa.h"
#include "pq/saber_api.h"
#include "pq/kyber_verify.h"
#include "pq/saber_fips202.h"
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int crypto_saber_kem_keypair(unsigned char *pk, unsigned char *sk, 
  int(*f_rng)(void *, unsigned char *, size_t), void *p_rng)

{
  size_t i;
 
  indcpa_kem_keypair(pk, sk, f_rng, p_rng);					      // sk[0:SABER_INDCPA_SECRETKEYBYTES-1] <-- sk
  for(i=0;i<SABER_INDCPA_PUBLICKEYBYTES;i++)
    sk[i+SABER_INDCPA_SECRETKEYBYTES] = pk[i];			      // sk[SABER_INDCPA_SECRETKEYBYTES:SABER_INDCPA_SECRETKEYBYTES+SABER_INDCPA_SECRETKEYBYTES-1] <-- pk	

  sha3_256(sk+SABER_SECRETKEYBYTES-64, pk, SABER_INDCPA_PUBLICKEYBYTES);  // Then hash(pk) is appended.	

  f_rng(p_rng,sk+SABER_SECRETKEYBYTES-SABER_KEYBYTES , SABER_KEYBYTES );    // Remaining part of sk contains a pseudo-random number. 
								      																								// This is output when check in crypto_kem_dec() fails. 
  return(0);	
}
/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - unsigned char *c:       pointer to output cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - unsigned char *k:       pointer to output shared secret (an already allocated array of CRYPTO_BYTES bytes)
*              - const unsigned char *pk: pointer to input public key (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*              - const unsigned char *sk: pointer to input public key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/

int crypto_saber_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk,
  int(*f_rng)(void *, unsigned char *, size_t), void *p_rng)

{
  unsigned char kr[64];                             	  // Will contain key, coins
  unsigned char buf[64];                          

  f_rng(p_rng, buf, 32);

	sha3_256(buf,buf,32);            			  // BUF[0:31] <-- random message (will be used as the key for client) Note: hash doesnot release system RNG output

  sha3_256(buf+32, pk, SABER_INDCPA_PUBLICKEYBYTES);    // BUF[32:63] <-- Hash(public key);  Multitarget countermeasure for coins + contributory KEM 

  sha3_512(kr, buf, 64);				// kr[0:63] <-- Hash(buf[0:63]);  	
							  								// K^ <-- kr[0:31]
							  								// noiseseed (r) <-- kr[32:63];	

  indcpa_kem_enc(buf, kr+32, pk,  ct);	// buf[0:31] contains message; kr[32:63] contains randomness r;  		

  sha3_256(kr+32, ct, SABER_BYTES_CCA_DEC);              

  sha3_256(ss, kr, 64);                          					// hash concatenation of pre-k and h(c) to k 
  return(0);	
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - unsigned char *c:       pointer to output cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - unsigned char *k:       pointer to output shared secret (an already allocated array of CRYPTO_BYTES bytes)
*              - const unsigned char *pk: pointer to input public key (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*              - const unsigned char *sk: pointer to input public key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 for sucess or -1 for failure
*
* On failure, ss will contain a randomized value.
**************************************************/

int crypto_saber_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{
  size_t i;
  int fail;
  unsigned char cmp[SABER_BYTES_CCA_DEC];
  unsigned char buf[64];
  unsigned char kr[64];                             // Will contain key, coins
  const unsigned char *pk = sk + SABER_INDCPA_SECRETKEYBYTES;

  indcpa_kem_dec(sk, ct, buf);			     // buf[0:31] <-- message

 
  // Multitarget countermeasure for coins + contributory KEM 
  for(i=0;i<32;i++)                                  // Save hash by storing h(pk) in sk 
    buf[32+i] = sk[SABER_SECRETKEYBYTES-64+i]; 

  sha3_512(kr, buf, 64);

  indcpa_kem_enc(buf, kr+32, pk, cmp);

  fail = verify(ct, cmp, SABER_BYTES_CCA_DEC);

  sha3_256(kr+32, ct, SABER_BYTES_CCA_DEC);        		     // overwrite coins in kr with h(c)  

  cmov(kr, sk+SABER_SECRETKEYBYTES-SABER_KEYBYTES, SABER_KEYBYTES, fail); 

  sha3_256(ss, kr, 64);                          	   	     // hash concatenation of pre-k and h(c) to k
  return -fail;	
}


//MBEDTLS

/**
* Generates a public key and a TLS ServerKeyExchange payload.
*/
int mbedtls_saber_make_params(mbedtls_saber_context *ctx, size_t *olen,
  unsigned char *buf, size_t blen,
  int(*f_rng)(void *, unsigned char *, size_t),
  void *p_rng)
{
  int ret;
  size_t len;

  if (ctx == NULL)
    return(MBEDTLS_ERR_SABER_BAD_INPUT_DATA);

  if ((ret = mbedtls_saber_genkey(ctx, f_rng, p_rng))
    != 0)
    return(ret);

  if ((SABER_POLYVECCOMPRESSEDBYTES + sizeof(&ctx->key.pk_hash) + sizeof(&ctx->key.pk_seed)) > blen)
  {
    return (MBEDTLS_ERR_SABER_BUFFER_TOO_SMALL);
  }

  len = 0;
  mbedtls_mpi_write_binary(&ctx->key.pk_poly, buf, SABER_POLYVECCOMPRESSEDBYTES);
  len += SABER_POLYVECCOMPRESSEDBYTES;
  memcpy(buf + len, &ctx->key.pk_hash, SABER_HASHBYTES);
  len += SABER_HASHBYTES;
  memcpy(buf + len, &ctx->key.pk_seed, SABER_SEEDBYTES);
  len += SABER_SEEDBYTES;

  *olen = len;
  return(0);
}

/*
* Reads a ServerKeyExhange payload. 
*/

int mbedtls_saber_read_params(mbedtls_saber_context *ctx,
  const unsigned char **buf, const unsigned char *end)
{
  int ret;
  size_t len;

  if (ctx == NULL)
    return(MBEDTLS_ERR_SABER_BAD_INPUT_DATA);

  if ((SABER_POLYVECCOMPRESSEDBYTES + sizeof(&ctx->key.pk_hash) + sizeof(&ctx->key.pk_seed)) > (end - *buf))
  {
    return (MBEDTLS_ERR_SABER_BAD_INPUT_DATA);
  }

  len = 0;
  mbedtls_mpi_read_binary(&ctx->key.pk_poly, *buf, SABER_POLYVECCOMPRESSEDBYTES);
  (*buf) += SABER_POLYVECCOMPRESSEDBYTES;
  memcpy(&ctx->key.pk_hash, (*buf), SABER_HASHBYTES);
  (*buf) += SABER_HASHBYTES;
  memcpy(&ctx->key.pk_seed, (*buf), SABER_SEEDBYTES);
  (*buf) += SABER_SEEDBYTES;

  return (0);
}

/**
* Generates a TLS ClientKeyExchange payload.
*/

int mbedtls_saber_make_public(mbedtls_saber_context *ctx, size_t *olen,
  unsigned char *buf, size_t blen,
  int(*f_rng)(void *, unsigned char *, size_t),
  void *p_rng)
{
  if (ctx == NULL)
    return(MBEDTLS_ERR_SABER_BAD_INPUT_DATA);

  mbedtls_saber_enc(ctx, f_rng, p_rng);

  mbedtls_mpi_write_binary(&ctx->key.ct, buf, CRYPTO_CIPHERTEXTBYTES_S);
  *olen = CRYPTO_CIPHERTEXTBYTES_S;

  return (0);
}

/**
* Reads a TLS ClientKeyExchange payload.
*/

int mbedtls_saber_read_public(mbedtls_saber_context *ctx,
  const unsigned char *buf, size_t blen)
{
  if (ctx == NULL)
    return(MBEDTLS_ERR_SABER_BAD_INPUT_DATA);

  if (CRYPTO_CIPHERTEXTBYTES_S > blen)
  {
    return(MBEDTLS_ERR_SABER_BAD_INPUT_DATA);
  }

  mbedtls_mpi_read_binary(&ctx->key.ct, buf, CRYPTO_CIPHERTEXTBYTES_S);
  return (0);
}

int mbedtls_saber_calc_secret(mbedtls_saber_context *ctx, size_t *olen,
  unsigned char *buf, size_t blen)
{
  if (ctx == NULL)
    return(MBEDTLS_ERR_SABER_BAD_INPUT_DATA);

  if (CRYPTO_BYTES_S > blen)
  {
    return(MBEDTLS_ERR_SABER_BAD_INPUT_DATA);
  }

  if (ctx->key.ss.n == 0)
  {
    mbedtls_saber_dec(ctx);
  }

  mbedtls_mpi_write_binary(&ctx->key.ss, buf, CRYPTO_BYTES_S);
  *olen = CRYPTO_BYTES_S;

  return (0);
}

int mbedtls_saber_genkey(mbedtls_saber_context *ctx,
  int(*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
  unsigned char pk[CRYPTO_PUBLICKEYBYTES_S];
  unsigned char sk[CRYPTO_SECRETKEYBYTES_S];

  crypto_kem_keypair(pk, sk, f_rng, p_rng);

  mbedtls_mpi_read_binary(&ctx->key.sk_poly, sk, SABER_INDCPA_SECRETKEYBYTES);
  memcpy(&ctx->key.sk_seed, sk + (SABER_SECRETKEYBYTES - SABER_SEEDBYTES), SABER_SEEDBYTES);
  mbedtls_mpi_read_binary(&ctx->key.pk_poly, pk, SABER_POLYVECCOMPRESSEDBYTES);
  memcpy(&ctx->key.pk_hash, sk + SABER_SECRETKEYBYTES - (2 * SABER_HASHBYTES), SABER_HASHBYTES);
  memcpy(&ctx->key.pk_seed, pk + SABER_POLYVECCOMPRESSEDBYTES, SABER_SEEDBYTES);

  
  /*printf("Secret Key: \n");
  for (int i = 0; i < CRYPTO_SECRETKEYBYTES_S; i++)
  {
    printf("%02X", sk[i]);
  }
  printf("Secret Seed: \n");
  for (int i = 0; i < SABER_SEEDBYTES; i++)
  {
    printf("%02X", ctx->key.sk_seed[i]);
  }
  printf("Public Key: \n");
  for (int i = 0; i < CRYPTO_PUBLICKEYBYTES_S; i++)
  {
    printf("%02X", pk[i]);
  }
  printf("Public Seed: \n");
  for (int i = 0; i < SABER_SEEDBYTES; i++)
  {
    printf("%02X", ctx->key.pk_seed[i]);
  }
  printf("\n");*/
  

  return (0);
}

int mbedtls_saber_enc(mbedtls_saber_context *ctx, 
            int(*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
  unsigned char ss[CRYPTO_BYTES_S];
  unsigned char ct[CRYPTO_CIPHERTEXTBYTES_S];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES_S];

  mbedtls_mpi_write_binary(&ctx->key.pk_poly, pk, SABER_POLYVECCOMPRESSEDBYTES);
  memcpy(pk + SABER_POLYVECCOMPRESSEDBYTES, &ctx->key.pk_seed, SABER_SEEDBYTES);

  crypto_kem_enc(ct, ss, pk, f_rng, p_rng);

  mbedtls_mpi_read_binary(&ctx->key.ss, ss, CRYPTO_BYTES_S);
  mbedtls_mpi_read_binary(&ctx->key.ct, ct, CRYPTO_CIPHERTEXTBYTES_S);
  return (0);
}

int mbedtls_saber_dec(mbedtls_saber_context *ctx)
{
  unsigned char ss[CRYPTO_BYTES_S];
  unsigned char ct[CRYPTO_CIPHERTEXTBYTES_S];
  unsigned char sk[CRYPTO_SECRETKEYBYTES_S];

  mbedtls_mpi_write_binary(&ctx->key.sk_poly, sk, SABER_INDCPA_SECRETKEYBYTES);
  mbedtls_mpi_write_binary(&ctx->key.pk_poly, sk + SABER_INDCPA_SECRETKEYBYTES, SABER_POLYVECCOMPRESSEDBYTES);
  memcpy(sk + SABER_INDCPA_SECRETKEYBYTES + SABER_POLYVECCOMPRESSEDBYTES, &ctx->key.pk_seed, SABER_SEEDBYTES);
  memcpy(sk + SABER_SECRETKEYBYTES - (2 * SABER_SEEDBYTES), &ctx->key.pk_hash, SABER_HASHBYTES);
  memcpy(sk + SABER_SECRETKEYBYTES - SABER_SEEDBYTES, &ctx->key.sk_seed, SABER_SEEDBYTES);

  mbedtls_mpi_write_binary(&ctx->key.ct, ct, CRYPTO_CIPHERTEXTBYTES_S);

  crypto_kem_dec(ss, ct, sk);

  mbedtls_mpi_read_binary(&ctx->key.ss, ss, CRYPTO_BYTES_S);
  return (0);
}

int mbedtls_saber_check_pub_priv(const mbedtls_saber_context *pub, const mbedtls_saber_context *prv)
{
  if (memcmp(&pub->key.pk_hash, &prv->key.pk_hash, SABER_HASHBYTES) ||
    memcmp(&pub->key.pk_seed, &prv->key.pk_seed, SABER_SEEDBYTES))
  {
    return -1;
  }
  return 0;
}

/*
* Initialize context
*/
void mbedtls_saber_init(mbedtls_saber_context *ctx)
{
  mbedtls_mpi_init(&ctx->key.sk_poly);
  mbedtls_mpi_init(&ctx->key.pk_poly);
  mbedtls_mpi_init(&ctx->key.ss);
  mbedtls_mpi_init(&ctx->key.ct);
}


/*
* Free context
*/
void mbedtls_saber_free(mbedtls_saber_context *ctx)
{
  mbedtls_mpi_free(&ctx->key.sk_poly);
  mbedtls_mpi_free(&ctx->key.pk_poly);
  mbedtls_mpi_free(&ctx->key.ss);
  mbedtls_mpi_free(&ctx->key.ct);
}



