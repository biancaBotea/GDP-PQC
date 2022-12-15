#include <stdint.h>
#include "pq/dilithium_params.h"
#include "pq/dilithium.h"
#include "pq/dilithium_packing.h"
#include "pq/dilithium_polyvec.h"
#include "pq/dilithium_poly.h"
#include "pq/dilithium_fips202.h"
#include "mbedtls/md.h"
#include "mbedtls/platform.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ASN1_PARSE_C)

#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/base64.h"
#include "mbedtls/platform_util.h"

#include <string.h>
#include "pq/dilithium_params.h"
#endif /* MBEDTLS_ASN1_PARSE_C */

/*int mbedtls_dilithium_genkey( mbedtls_dilithium_context *ctx, int(*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{


	/* DILITHIUM_key ::= SEQUENCE {
		* SecretKey BIT STRING ,
		* PublicKey BIT STRING
	* }
  */
  /*if (crypto_sign_keypair_d(ctx->pk, ctx->sk, f_rng, p_rng)) {
		return -1;
	}
	/*unsigned char *buf, *c;
	size_t len = 0;
	size_t *final_buf_bytes_written;
	buf = (unsigned char *) malloc(6000);
  int ret = 0;
	c = buf + 6000;*/

  /*mbedtls_printf( "\ngenerating key\n" );
	// Write keys to buffer in ASN .1 format
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_bitstring(&c, buf, ctx->pk, 
		CRYPTO_PUBLICKEYBYTES_D * 8));
  mbedtls_printf( " 48\n" );
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_bitstring(&c, buf, ctx->sk, 
		CRYPTO_SECRETKEYBYTES_D * 8));
	mbedtls_printf( " 51\n" );
  MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
	mbedtls_printf( " 53\n" );
  MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf, 
		MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ));
  mbedtls_printf( " 56\n" );
  
	//Base64 encoding the written buffer
	size_t final_buf_size = 4*(len / 3 + (len % 3 != 0));
	final_buf_bytes_written = (size_t *) malloc(16);
  mbedtls_printf("final_buf_size = %d, len = %d, buf: %u\n", final_buf_size, len, buf);
	mbedtls_base64_encode(final_buf, final_buf_size + 1, 
		final_buf_bytes_written, buf, len);
  mbedtls_printf( " 63\n" );
  
	return ( 0 );
}*/





/* 
 * Generates a Dilithium keypair.
 */

int mbedtls_dilithium_genkey(mbedtls_dilithium_context *ctx,
							int(*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
	int ret;
  printf("CRYPTO_PUBLICKEYBYTES_D = %d, CRYPTO_SECRETKEYBYTES_D = %d\n", CRYPTO_PUBLICKEYBYTES_D, CRYPTO_SECRETKEYBYTES_D);
	unsigned char pkey[CRYPTO_PUBLICKEYBYTES_D];
	unsigned char skey[CRYPTO_SECRETKEYBYTES_D + CRYPTO_PUBLICKEYBYTES_D];

  //Initialize with random data 
  printf("Initialising sk with random data\n");
	do {
		MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(&ctx->sk, 632, f_rng, p_rng));
	} while (mbedtls_mpi_bitlen(&ctx->sk) == 0);
  printf("Initialising pk with random data\n");
	do {
		MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(&ctx->pk, 656, f_rng, p_rng));
	} while (mbedtls_mpi_bitlen(&ctx->sk) == 0);

	mbedtls_mpi_write_binary(&ctx->sk, skey + 0, 2528);
	mbedtls_mpi_write_binary(&ctx->pk, skey + 1 * 2528, 2624);
  
	if (crypto_sign_keypair_d(pkey, skey, f_rng, p_rng)) {
		return -1;
	}
	mbedtls_mpi_read_binary(&ctx->sk, skey + 0, 2528);
	mbedtls_mpi_read_binary(&ctx->pk, skey + 1 * 2528, 2624);

cleanup:
	if (ret != 0)
		return(ret);

	return ( 0 );
}


/*
* Initialize context
*/
void mbedtls_dilithium_init(mbedtls_dilithium_context *ctx){

  memset ( ctx -> pk , 0 , CRYPTO_PUBLICKEYBYTES_D ) ;
  memset ( ctx -> sk , 0 , CRYPTO_SECRETKEYBYTES_D ) ;
}

/*
* Free context
*/
void mbedtls_dilithium_free(mbedtls_dilithium_context *ctx){

  // if(ctx == NULL)
  //   return;

  mbedtls_mpi_free(&ctx->pk);
  mbedtls_mpi_free(&ctx->sk);
}

/**
 * \brief          Returns the length of the Dilithium public-key in Bytes.
 *
 * \param ctx      The initialized dilithium context.
 *
 * \return         The length of the dilithium public-key in Bytes.
 *
 */
size_t mbedtls_dilithium_get_len( const mbedtls_dilithium_context *ctx ){

  // return( ctx->len );

  return sizeof(ctx->pk);
}

/**
* \brief           This function computes the dilithium signature and writes it
*                  to a buffer.
*
* \warning         It is not thread-safe to use the same context in
*                  multiple threads.
*
* \param ctx       The dilithium context.
* \param hash      The message hash.
* \param hlen      The length of the hash.
* \param sig       The buffer that holds the signature.
* \param slen      The length of the signature written.
*
* \return          \c 0 on success
*                  or an error code on failure.
*/
int mbedtls_dilithium_write_signature(mbedtls_dilithium_context *ctx,
  //mbedtls_md_type_t md_alg,
  const unsigned char *hash, size_t hlen,
  unsigned char *sig, size_t *slen,
  int(*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
  int ret = 0;
  unsigned char skey[2 * N_D];
  unsigned char optrand[N_D];
  unsigned long long ull_slen = 0;

  mbedtls_mpi_write_binary(&ctx->sk, skey + 0 * N_D, N_D);
  mbedtls_mpi_write_binary(&ctx->pk, skey + 1 * N_D, N_D);
  // mbedtls_mpi_write_binary(&ctx->key.pk_seed, sk + 2 * SPX_N, SPX_N);
  // mbedtls_mpi_write_binary(&ctx->key.root, sk + 3 * SPX_N, SPX_N);

  // sphincs_md_info_t *md;
  // if (ctx->key.md_alg == MBEDTLS_MD_SHA256)
  // {
  //   md = &sphincs_sha256_info;
  // }
  // else
  // {
  //   md = &sphincs_shake256_info;
  // }
  
  if ((ret = f_rng(p_rng, optrand, N_D)) != 0)
    return ret;

  ret = crypto_sign_d(sig, &ull_slen, hash, hlen, skey);
  *slen = (size_t)ull_slen;

  return (0);
}

/**
* \brief           This function computes the dilithium signature and writes it
*                  to a buffer.
*
* \warning         It is not thread-safe to use the same context in
*                  multiple threads.
*
* \param ctx       The dilithium context.
* \param hash      The message hash.
* \param hlen      The length of the hash.
* \param sig       The buffer that holds the signature.
* \param slen      The length of the signature written.
*
* \return          \c 0 on success
*                  or an error code on failure.
*/
int mbedtls_dilithium_read_signature(mbedtls_dilithium_context *ctx,
  //mbedtls_md_type_t md_alg,
  const unsigned char *hash, size_t hlen,
  const unsigned char *sig, size_t slen)
{
  unsigned char pkey[2 * N_D];

  mbedtls_mpi_write_binary(&ctx->pk, pkey + 1 * N_D, N_D);

  //mbedtls_mpi_write_file("Root:    ", &ctx->key.root, 16, NULL);
  //mbedtls_mpi_write_file("PK_D_Seed: ", &ctx->key.pk_seed, 16, NULL);

  // sphincs_md_info_t *md;
  // if (ctx->key.md_alg == MBEDTLS_MD_SHA256)
  // {
  //   md = &sphincs_sha256_info;
  // }
  // else
  // {
  //   md = &sphincs_shake256_info;
  // }

  return crypto_sign_open_d(hash, hlen, sig, slen, pkey);
}

/*************************************************
* Name:        crypto_sign_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - unsigned char *pk: pointer to output public key (allocated
*                             array of CRYPTO_PUBLICK_DEYBYTES_D bytes)
*              - unsigned char *sk: pointer to output private key (allocated
*                             array of CRYPTO_SECRETK_DEYBYTES_D bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_sign_keypair_d(unsigned char *pk, unsigned char *sk,
      int(*f_rng)(void *, unsigned char *, size_t), void *p_rng) {
  unsigned char seedbuf[2*SEEDBYTES_D + CRHBYTES];
  unsigned char tr[SEEDBYTES_D];
  const unsigned char *rho, *rhoprime, *key;
  polyvecl mat[K_D];
  polyvecl s1, s1hat;
  polyveck s2, t1, t0;

  /* Get randomness for rho, rhoprime and key */
  f_rng(p_rng, seedbuf, SEEDBYTES_D);
  shake256_d(seedbuf, 2*SEEDBYTES_D + CRHBYTES, seedbuf, SEEDBYTES_D);
  rho = seedbuf;
  rhoprime = rho + SEEDBYTES_D;
  key = rhoprime + CRHBYTES;

  /* Expand matrix */
  polyvec_matrix_expand(mat, rho);

  /* Sample short vectors s1 and s2 */
  polyvecl_uniform_eta(&s1, rhoprime, 0);
  polyveck_uniform_eta(&s2, rhoprime, L_D);

  /* Matrix-vector multiplication */
  s1hat = s1;
  polyvecl_ntt(&s1hat);
  polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
  polyveck_reduce(&t1);
  polyveck_invntt_tomont(&t1);

  /* Add error vector s2 */
  polyveck_add(&t1, &t1, &s2);

  /* Extract t1 and write public key */
  polyveck_caddq(&t1);
  polyveck_power2round(&t1, &t0, &t1);
  pack_pk(pk, rho, &t1);

  /* Compute H(rho, t1) and write secret key */
  shake256_d(tr, SEEDBYTES_D, pk, CRYPTO_PUBLICKEYBYTES_D);
  pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

  return 0;
}

/*************************************************
* Name:        crypto_sign_signature
*
* Description: Computes signature.
*
* Arguments:   - unsigned char *sig:   pointer to output signature (of length CRYPTO_BYTES_D)
*              - size_t *siglen: pointer to output length of signature
*              - unsigned char *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - unsigned char *sk:    pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign_signature_d(unsigned char *sig,
                          size_t *siglen,
                          const unsigned char *m,
                          size_t mlen,
                          const unsigned char *sk)
{
  unsigned int n;
  unsigned char seedbuf[3*SEEDBYTES_D + 2*CRHBYTES];
  unsigned char *rho, *tr, *key, *mu, *rhoprime;
  uint16_t nonce = 0;
  polyvecl mat[K_D], s1, y, z;
  polyveck t0, s2, w1, w0, h;
  poly cp;
  keccak_state state;

  rho = seedbuf;
  tr = rho + SEEDBYTES_D;
  key = tr + SEEDBYTES_D;
  mu = key + SEEDBYTES_D;
  rhoprime = mu + CRHBYTES;
  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  /* Compute CRH(tr, msg) */
  shake256_init_d(&state);
  shake256_absorb_d(&state, tr, SEEDBYTES_D);
  shake256_absorb_d(&state, m, mlen);
  shake256_finalize_d(&state);
  shake256_squeeze_d(mu, CRHBYTES, &state);

#ifdef DILITHIUM_RANDOMIZED_SIGNING
  randombytes(rhoprime, CRHBYTES);
#else
  shake256_d(rhoprime, CRHBYTES, key, SEEDBYTES_D + CRHBYTES);
#endif

  /* Expand matrix and transform vectors */
  polyvec_matrix_expand(mat, rho);
  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);
  polyveck_ntt(&t0);

rej:
  /* Sample intermediate vector y */
  polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

  /* Matrix-vector multiplication */
  z = y;
  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Decompose w and call the random oracle */
  polyveck_caddq(&w1);
  polyveck_decompose(&w1, &w0, &w1);
  polyveck_pack_w1(sig, &w1);

  shake256_init_d(&state);
  shake256_absorb_d(&state, mu, CRHBYTES);
  shake256_absorb_d(&state, sig, K_D*POLYW1_PACKEDBYTES);
  shake256_finalize_d(&state);
  shake256_squeeze_d(sig, SEEDBYTES_D, &state);
  poly_challenge(&cp, sig);
  poly_ntt_D(&cp);

  /* Compute z, reject if it reveals secret */
  polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
  polyvecl_invntt_tomont(&z);
  polyvecl_add(&z, &z, &y);
  polyvecl_reduce(&z);
  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    goto rej;

  /* Check that subtracting cs2 does not change high bits of w and low bits
   * do not reveal secret information */
  polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
  polyveck_invntt_tomont(&h);
  polyveck_sub(&w0, &w0, &h);
  polyveck_reduce(&w0);
  if(polyveck_chknorm(&w0, GAMMA2 - BETA))
    goto rej;

  /* Compute hints for w1 */
  polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
  polyveck_invntt_tomont(&h);
  polyveck_reduce(&h);
  if(polyveck_chknorm(&h, GAMMA2))
    goto rej;

  polyveck_add(&w0, &w0, &h);
  n = polyveck_make_hint(&h, &w0, &w1);
  if(n > OMEGA)
    goto rej;

  /* Write signature */
  pack_sig(sig, sig, &z, &h);
  *siglen = CRYPTO_BYTES_D;
  return 0;
}

/*************************************************
* Name:        crypto_sign
*
* Description: Compute signed message.
*
* Arguments:   - unsigned char *sm: pointer to output signed message (allocated
*                             array with CRYPTO_BYTES_D + mlen bytes),
*                             can be equal to m
*              - size_t *smlen: pointer to output length of signed
*                               message
*              - const unsigned char *m: pointer to message to be signed
*              - size_t mlen: length of message
*              - const unsigned char *sk: pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign_d(unsigned char *sm,
                size_t *smlen,
                const unsigned char *m,
                size_t mlen,
                const unsigned char *sk)
{
  size_t i;

  for(i = 0; i < mlen; ++i)
    sm[CRYPTO_BYTES_D + mlen - 1 - i] = m[mlen - 1 - i];
  crypto_sign_signature_d(sm, smlen, sm + CRYPTO_BYTES_D, mlen, sk);
  *smlen += mlen;
  return 0;
}

/*************************************************
* Name:        crypto_sign_verify
*
* Description: Verifies signature.
*
* Arguments:   - unsigned char *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const unsigned char *m: pointer to message
*              - size_t mlen: length of message
*              - const unsigned char *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_verify_d(const unsigned char *sig,
                       size_t siglen,
                       const unsigned char *m,
                       size_t mlen,
                       const unsigned char *pk)
{
  unsigned int i;
  unsigned char buf[K_D*POLYW1_PACKEDBYTES];
  unsigned char rho[SEEDBYTES_D];
  unsigned char mu[CRHBYTES];
  unsigned char c[SEEDBYTES_D];
  unsigned char c2[SEEDBYTES_D];
  poly cp;
  polyvecl mat[K_D], z;
  polyveck t1, w1, h;
  keccak_state state;

  if(siglen != CRYPTO_BYTES_D)
    return -1;

  unpack_pk(rho, &t1, pk);
  if(unpack_sig(c, &z, &h, sig))
    return -1;
  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    return -1;

  /* Compute CRH(H(rho, t1), msg) */
  shake256_d(mu, SEEDBYTES_D, pk, CRYPTO_PUBLICKEYBYTES_D);
  shake256_init_d(&state);
  shake256_absorb_d(&state, mu, SEEDBYTES_D);
  shake256_absorb_d(&state, m, mlen);
  shake256_finalize_d(&state);
  shake256_squeeze_d(mu, CRHBYTES, &state);

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  poly_challenge(&cp, c);
  polyvec_matrix_expand(mat, rho);

  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

  poly_ntt_D(&cp);
  polyveck_shiftl(&t1);
  polyveck_ntt(&t1);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  polyveck_sub(&w1, &w1, &t1);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Reconstruct w1 */
  polyveck_caddq(&w1);
  polyveck_use_hint(&w1, &w1, &h);
  polyveck_pack_w1(buf, &w1);

  /* Call random oracle and verify challenge */
  shake256_init_d(&state);
  shake256_absorb_d(&state, mu, CRHBYTES);
  shake256_absorb_d(&state, buf, K_D*POLYW1_PACKEDBYTES);
  shake256_finalize_d(&state);
  shake256_squeeze_d(c2, SEEDBYTES_D, &state);
  for(i = 0; i < SEEDBYTES_D; ++i)
    if(c[i] != c2[i])
      return -1;

  return 0;
}

/*************************************************
* Name:        crypto_sign_open
*
* Description: Verify signed message.
*
* Arguments:   - unsigned char *m: pointer to output message (allocated
*                            array with smlen bytes), can be equal to sm
*              - size_t *mlen: pointer to output length of message
*              - const unsigned char *sm: pointer to signed message
*              - size_t smlen: length of signed message
*              - const unsigned char *pk: pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_open_d(unsigned char *m,
                     size_t *mlen,
                     const unsigned char *sm,
                     size_t smlen,
                     const unsigned char *pk)
{
  size_t i;

  if(smlen < CRYPTO_BYTES_D)
    goto badsig;

  *mlen = smlen - CRYPTO_BYTES_D;
  if(crypto_sign_verify_d(sm, CRYPTO_BYTES_D, sm + CRYPTO_BYTES_D, *mlen, pk))
    goto badsig;
  else {
    /* All good, copy msg, return 0 */
    for(i = 0; i < *mlen; ++i)
      m[i] = sm[CRYPTO_BYTES_D + i];
    return 0;
  }

badsig:
  /* Signature verification failed */
  *mlen = -1;
  for(i = 0; i < smlen; ++i)
    m[i] = 0;

  return -1;
}
