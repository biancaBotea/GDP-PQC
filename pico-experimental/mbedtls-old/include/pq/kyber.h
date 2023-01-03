#ifndef KYBER_H
#define KYBER_H

#include "mbedtls/bignum.h"
#include "pq/kyber_params.h"

/*
* KYBER error codes
*/
#define MBEDTLS_ERR_KYBER_BAD_INPUT_DATA                    -0x5081  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_KYBER_FEATURE_UNAVAILABLE               -0x5082  /**< New Hope key exchange is not available. */
#define MBEDTLS_ERR_KYBER_FAILED_TO_GENERATE_RANDOM         -0x5083  /**< Unable to generate sufficient random bytes. */
#define MBEDTLS_ERR_KYBER_BUFFER_TOO_SMALL                  -0x5000  /**< The buffer is too small to write to. */

#define CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define CRYPTO_BYTES           KYBER_SYMBYTES

#if   (KYBER_K == 2)
#define CRYPTO_ALGNAME "Kyber512"
#elif (KYBER_K == 3)
#define CRYPTO_ALGNAME "Kyber768"
#elif (KYBER_K == 4)
#define CRYPTO_ALGNAME "Kyber1024"
#else
#error "KYBER_K must be in {2,3,4}"
#endif

typedef struct
{
	unsigned int n;
	unsigned int k;
	unsigned int q;
}
mbedtls_kyber_params;


typedef struct
{
	mbedtls_mpi sk_poly;
	mbedtls_mpi pk_poly;
	mbedtls_mpi ss;
	mbedtls_mpi ct;
	unsigned char sk_seed[KYBER_SYMBYTES];
	unsigned char pk_hash[KYBER_SYMBYTES];
	unsigned char pk_seed[KYBER_SYMBYTES];
	size_t bitlen;
}
mbedtls_kyber_keypair;


typedef struct
{
	mbedtls_kyber_params params;
	mbedtls_kyber_keypair key;
}
mbedtls_kyber_context;

/* Reference Implementation */
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk,
						int(*f_rng)(void *, unsigned char *, size_t), void *p_rng);

int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk,
					int(*f_rng)(void *, unsigned char *, size_t), void *p_rng);

int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/* MBEDTLS */

/**
* Generates a public key and a TLS ServerKeyExchange payload.
*/
int mbedtls_kyber_make_params(mbedtls_kyber_context *ctx, size_t *olen,
	unsigned char *buf, size_t blen,
	int(*f_rng)(void *, unsigned char *, size_t),
	void *p_rng);

/*
* Reads a ServerKeyExhange payload. 
*/
int mbedtls_kyber_read_params(mbedtls_kyber_context *ctx,
	const unsigned char **buf, const unsigned char *end);

/**
* Generates a TLS ClientKeyExchange payload.
*/
int mbedtls_kyber_make_public(mbedtls_kyber_context *ctx, size_t *olen,
	unsigned char *buf, size_t blen,
	int(*f_rng)(void *, unsigned char *, size_t),
	void *p_rng);

/**
* Reads a TLS ClientKeyExchange payload.
*/
int mbedtls_kyber_read_public(mbedtls_kyber_context *ctx,
	const unsigned char *buf, size_t blen);

/**
* This function derives and exports the shared secret.
*/
int mbedtls_kyber_calc_secret(mbedtls_kyber_context *ctx, size_t *olen,
	unsigned char *buf, size_t blen);

int mbedtls_kyber_genkey(mbedtls_kyber_context *ctx,
	int(*f_rng)(void *, unsigned char *, size_t), void *p_rng);

int mbedtls_kyber_enc(mbedtls_kyber_context *ctx,
	int(*f_rng)(void *, unsigned char *, size_t), void *p_rng);

int mbedtls_kyber_dec(mbedtls_kyber_context *ctx);

int mbedtls_kyber_check_pub_priv(const mbedtls_kyber_context *pub, const mbedtls_kyber_context *prv);

void mbedtls_kyber_init(mbedtls_kyber_context *ctx);

void mbedtls_kyber_free(mbedtls_kyber_context *ctx);


#endif
