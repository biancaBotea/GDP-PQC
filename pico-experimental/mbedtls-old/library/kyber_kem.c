#include "pq/kyber.h"
#include "pq/fips202.h"
#include "pq/kyber_params.h"
#include "pq/kyber_verify.h"
#include "pq/kyber_indcpa.h"

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - unsigned char *pk: pointer to output public key (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*              - unsigned char *sk: pointer to output private key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk, 
	int(*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
  size_t i;
  indcpa_keypair(pk, sk, f_rng, p_rng);
  for(i=0;i<KYBER_INDCPA_PUBLICKEYBYTES;i++)
    sk[i+KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
  sha3_256(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES,pk,KYBER_PUBLICKEYBYTES);
  f_rng(p_rng, sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES);         /* Value z for pseudo-random output on reject */
  return 0;
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - unsigned char *ct:       pointer to output cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - unsigned char *ss:       pointer to output shared secret (an already allocated array of CRYPTO_BYTES bytes)
*              - const unsigned char *pk: pointer to input public key (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk,
					int(*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
  unsigned char  kr[2*KYBER_SYMBYTES];                                        /* Will contain key, coins */
  unsigned char buf[2*KYBER_SYMBYTES];                          

  f_rng(p_rng, buf, KYBER_SYMBYTES);
  sha3_256(buf,buf,KYBER_SYMBYTES);                                           /* Don't release system RNG output */

  sha3_256(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);                     /* Multitarget countermeasure for coins + contributory KEM */
  sha3_512(kr, buf, 2*KYBER_SYMBYTES);

  indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);                                 /* coins are in kr+KYBER_SYMBYTES */

  sha3_256(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);                     /* overwrite coins in kr with H(c) */
  sha3_256(ss, kr, 2*KYBER_SYMBYTES);                                         /* hash concatenation of pre-k and H(c) to k */
  return 0;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - unsigned char *ss:       pointer to output shared secret (an already allocated array of CRYPTO_BYTES bytes)
*              - const unsigned char *ct: pointer to input cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - const unsigned char *sk: pointer to input private key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 for sucess or -1 for failure
*
* On failure, ss will contain a randomized value.
**************************************************/
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{
  size_t i; 
  int fail;
  unsigned char cmp[KYBER_CIPHERTEXTBYTES];
  unsigned char buf[2*KYBER_SYMBYTES];
  unsigned char kr[2*KYBER_SYMBYTES];                                         /* Will contain key, coins, qrom-hash */
  const unsigned char *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

  indcpa_dec(buf, ct, sk);
                                                                              
  for(i=0;i<KYBER_SYMBYTES;i++)                                               /* Multitarget countermeasure for coins + contributory KEM */
    buf[KYBER_SYMBYTES+i] = sk[KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES+i];      /* Save hash by storing H(pk) in sk */
  sha3_512(kr, buf, 2*KYBER_SYMBYTES);

  indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES);                                /* coins are in kr+KYBER_SYMBYTES */

  fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

  sha3_256(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);                     /* overwrite coins in kr with H(c)  */

  cmov(kr, sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);     /* Overwrite pre-k with z on re-encryption failure */

  sha3_256(ss, kr, 2*KYBER_SYMBYTES);                                         /* hash concatenation of pre-k and H(c) to k */

  return -fail;
}

int mbedtls_kyber_make_params(mbedtls_kyber_context *ctx, size_t *olen,
	unsigned char *buf, size_t blen,
	int(*f_rng)(void *, unsigned char *, size_t),
	void *p_rng)
{
	int ret;
	size_t len;

	if (ctx == NULL)
		return(MBEDTLS_ERR_KYBER_BAD_INPUT_DATA);

	if ((ret = mbedtls_kyber_genkey(ctx, f_rng, p_rng))
		!= 0)
		return(ret);

	if ((KYBER_POLYVECCOMPRESSEDBYTES + sizeof(&ctx->key.pk_hash) + sizeof(&ctx->key.pk_seed)) > blen)
	{
		return (MBEDTLS_ERR_KYBER_BUFFER_TOO_SMALL);
	}

	len = 0;
	mbedtls_mpi_write_binary(&ctx->key.pk_poly, buf, KYBER_POLYVECCOMPRESSEDBYTES);
	len += KYBER_POLYVECCOMPRESSEDBYTES;
	memcpy(buf + len, &ctx->key.pk_hash, KYBER_SYMBYTES);
	len += KYBER_SYMBYTES;
	memcpy(buf + len, &ctx->key.pk_seed, KYBER_SYMBYTES);
	len += KYBER_SYMBYTES;

	*olen = len;
	return(0);
}

int mbedtls_kyber_read_params(mbedtls_kyber_context *ctx,
	const unsigned char **buf, const unsigned char *end)
{
	int ret;
	size_t len;

	if (ctx == NULL)
		return(MBEDTLS_ERR_KYBER_BAD_INPUT_DATA);

	if ((KYBER_POLYVECCOMPRESSEDBYTES + sizeof(&ctx->key.pk_hash) + sizeof(&ctx->key.pk_seed)) > (end - *buf))
	{
		return (MBEDTLS_ERR_KYBER_BAD_INPUT_DATA);
	}

	len = 0;
	mbedtls_mpi_read_binary(&ctx->key.pk_poly, *buf, KYBER_POLYVECCOMPRESSEDBYTES);
	(*buf) += KYBER_POLYVECCOMPRESSEDBYTES;
	memcpy(&ctx->key.pk_hash, (*buf), KYBER_SYMBYTES);
	(*buf) += KYBER_SYMBYTES;
	memcpy(&ctx->key.pk_seed, (*buf), KYBER_SYMBYTES);
	(*buf) += KYBER_SYMBYTES;

	return (0);
}

int mbedtls_kyber_make_public(mbedtls_kyber_context *ctx, size_t *olen,
	unsigned char *buf, size_t blen,
	int(*f_rng)(void *, unsigned char *, size_t),
	void *p_rng)
{
	if (ctx == NULL)
		return(MBEDTLS_ERR_KYBER_BAD_INPUT_DATA);

	mbedtls_kyber_enc(ctx, f_rng, p_rng);

	mbedtls_mpi_write_binary(&ctx->key.ct, buf, CRYPTO_CIPHERTEXTBYTES);
	*olen = CRYPTO_CIPHERTEXTBYTES;

	return (0);
}

int mbedtls_kyber_read_public(mbedtls_kyber_context *ctx,
	const unsigned char *buf, size_t blen)
{
	if (ctx == NULL)
		return(MBEDTLS_ERR_KYBER_BAD_INPUT_DATA);

	if (CRYPTO_CIPHERTEXTBYTES > blen)
	{
		return(MBEDTLS_ERR_KYBER_BAD_INPUT_DATA);
	}

	mbedtls_mpi_read_binary(&ctx->key.ct, buf, CRYPTO_CIPHERTEXTBYTES);
	return (0);
}

int mbedtls_kyber_calc_secret(mbedtls_kyber_context *ctx, size_t *olen,
	unsigned char *buf, size_t blen)
{
	if (ctx == NULL)
		return(MBEDTLS_ERR_KYBER_BAD_INPUT_DATA);

	if (CRYPTO_BYTES > blen)
	{
		return(MBEDTLS_ERR_KYBER_BAD_INPUT_DATA);
	}

	if (ctx->key.ss.n == 0)
	{
		mbedtls_kyber_dec(ctx);
	}

	mbedtls_mpi_write_binary(&ctx->key.ss, buf, CRYPTO_BYTES);
	*olen = CRYPTO_BYTES;

	return (0);
}

int mbedtls_kyber_genkey(mbedtls_kyber_context *ctx,
	int(*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
	unsigned char pk[CRYPTO_PUBLICKEYBYTES];
	unsigned char sk[CRYPTO_SECRETKEYBYTES];

	crypto_kem_keypair(pk, sk, f_rng, p_rng);

	mbedtls_mpi_read_binary(&ctx->key.sk_poly, sk, KYBER_INDCPA_SECRETKEYBYTES);
	memcpy(&ctx->key.sk_seed, sk + (KYBER_SECRETKEYBYTES - KYBER_SYMBYTES), KYBER_SYMBYTES);
	mbedtls_mpi_read_binary(&ctx->key.pk_poly, pk, KYBER_POLYVECCOMPRESSEDBYTES);
	memcpy(&ctx->key.pk_hash, sk + KYBER_SECRETKEYBYTES - (2 * KYBER_SYMBYTES), KYBER_SYMBYTES);
	memcpy(&ctx->key.pk_seed, pk + KYBER_POLYVECCOMPRESSEDBYTES, KYBER_SYMBYTES);

	/*
	printf("Secret Key: \n");
	for (int i = 0; i < CRYPTO_SECRETKEYBYTES; i++)
	{
		printf("%02X", sk[i]);
	}
	printf("Secret Seed: \n");
	for (int i = 0; i < KYBER_SYMBYTES; i++)
	{
		printf("%02X", ctx->key.sk_seed[i]);
	}
	printf("Public Key: \n");
	for (int i = 0; i < CRYPTO_PUBLICKEYBYTES; i++)
	{
		printf("%02X", pk[i]);
	}
	printf("Public Seed: \n");
	for (int i = 0; i < KYBER_SYMBYTES; i++)
	{
		printf("%02X", ctx->key.pk_seed[i]);
	}
	printf("\n");
	*/

	return (0);
}

int mbedtls_kyber_enc(mbedtls_kyber_context *ctx, 
					  int(*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
	unsigned char ss[CRYPTO_BYTES];
	unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
	unsigned char pk[CRYPTO_PUBLICKEYBYTES];

	mbedtls_mpi_write_binary(&ctx->key.pk_poly, pk, KYBER_POLYVECCOMPRESSEDBYTES);
	memcpy(pk + KYBER_POLYVECCOMPRESSEDBYTES, &ctx->key.pk_seed, KYBER_SYMBYTES);

	crypto_kem_enc(ct, ss, pk, f_rng, p_rng);

	mbedtls_mpi_read_binary(&ctx->key.ss, ss, CRYPTO_BYTES);
	mbedtls_mpi_read_binary(&ctx->key.ct, ct, CRYPTO_CIPHERTEXTBYTES);
	return (0);
}

int mbedtls_kyber_dec(mbedtls_kyber_context *ctx)
{
	unsigned char ss[CRYPTO_BYTES];
	unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
	unsigned char sk[CRYPTO_SECRETKEYBYTES];

	mbedtls_mpi_write_binary(&ctx->key.sk_poly, sk, KYBER_INDCPA_SECRETKEYBYTES);
	mbedtls_mpi_write_binary(&ctx->key.pk_poly, sk + KYBER_INDCPA_SECRETKEYBYTES, KYBER_POLYVECCOMPRESSEDBYTES);
	memcpy(sk + KYBER_INDCPA_SECRETKEYBYTES + KYBER_POLYVECCOMPRESSEDBYTES, &ctx->key.pk_seed, KYBER_SYMBYTES);
	memcpy(sk + KYBER_SECRETKEYBYTES - (2 * KYBER_SYMBYTES), &ctx->key.pk_hash, KYBER_SYMBYTES);
	memcpy(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, &ctx->key.sk_seed, KYBER_SYMBYTES);

	mbedtls_mpi_write_binary(&ctx->key.ct, ct, CRYPTO_CIPHERTEXTBYTES);

	crypto_kem_dec(ss, ct, sk);

	mbedtls_mpi_read_binary(&ctx->key.ss, ss, CRYPTO_BYTES);
	return (0);
}

int mbedtls_kyber_check_pub_priv(const mbedtls_kyber_context *pub, const mbedtls_kyber_context *prv)
{
	if (memcmp(&pub->key.pk_hash, &prv->key.pk_hash, KYBER_SYMBYTES) ||
		memcmp(&pub->key.pk_seed, &prv->key.pk_seed, KYBER_SYMBYTES))
	{
		return -1;
	}
	return 0;
}

/*
* Initialize context
*/
void mbedtls_kyber_init(mbedtls_kyber_context *ctx)
{
	mbedtls_mpi_init(&ctx->key.sk_poly);
	mbedtls_mpi_init(&ctx->key.pk_poly);
	mbedtls_mpi_init(&ctx->key.ss);
	mbedtls_mpi_init(&ctx->key.ct);
}


/*
* Free context
*/
void mbedtls_kyber_free(mbedtls_kyber_context *ctx)
{
	mbedtls_mpi_free(&ctx->key.sk_poly);
	mbedtls_mpi_free(&ctx->key.pk_poly);
	mbedtls_mpi_free(&ctx->key.ss);
	mbedtls_mpi_free(&ctx->key.ct);
}
