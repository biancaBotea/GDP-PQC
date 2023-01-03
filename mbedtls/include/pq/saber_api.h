#ifndef SABER_API_H
#define SABER_API_H

#include "saber_params.h"
#include "mbedtls/bignum.h"

#if SABER_L == 2
	#define CRYPTO_ALGNAME "LightSaber"
#elif SABER_L == 3
	#define CRYPTO_ALGNAME "Saber"
#elif SABER_L == 4
	#define CRYPTO_ALGNAME "FireSaber"
#else
	#error "Unsupported SABER parameter."
#endif


/*
* SABER error codes
*/
#define MBEDTLS_ERR_SABER_BAD_INPUT_DATA                    -0x5084  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_SABER_FEATURE_UNAVAILABLE               -0x5085  /**< New Hope key exchange is not available. */
#define MBEDTLS_ERR_SABER_FAILED_TO_GENERATE_RANDOM         -0x5086  /**< Unable to generate sufficient random bytes. */
#define MBEDTLS_ERR_SABER_BUFFER_TOO_SMALL                  -0x5087  /**< The buffer is too small to write to. */

#define CRYPTO_SECRETKEYBYTES_S SABER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES_S SABER_PUBLICKEYBYTES
#define CRYPTO_BYTES_S SABER_KEYBYTES
#define CRYPTO_CIPHERTEXTBYTES_S SABER_BYTES_CCA_DEC

typedef struct
{
	unsigned int n;
	unsigned int eq;
	unsigned int ep;
	unsigned int et;
	unsigned int mu;
}
mbedtls_saber_params;

typedef struct
{
	mbedtls_mpi sk_poly;
	mbedtls_mpi pk_poly;
	mbedtls_mpi ss;
	mbedtls_mpi ct;
	unsigned char sk_seed[SABER_SEEDBYTES];
	unsigned char pk_hash[SABER_HASHBYTES];
	unsigned char pk_seed[SABER_SEEDBYTES];
	size_t bitlen;
}
mbedtls_saber_keypair;


typedef struct
{
	mbedtls_saber_params params;
	mbedtls_saber_keypair key;
}
mbedtls_saber_context;

int crypto_saber_kem_keypair(unsigned char *pk, unsigned char *sk, int(*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int crypto_saber_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk, int(*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int crypto_saber_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/* MBEDTLS */

/**
* Generates a public key and a TLS ServerKeyExchange payload.
*/
int mbedtls_saber_make_params(mbedtls_saber_context *ctx, size_t *olen,
	unsigned char *buf, size_t blen,
	int(*f_rng)(void *, unsigned char *, size_t),
	void *p_rng);

/*
* Reads a ServerKeyExhange payload. 
*/
int mbedtls_saber_read_params(mbedtls_saber_context *ctx,
	const unsigned char **buf, const unsigned char *end);

/**
* Generates a TLS ClientKeyExchange payload.
*/
int mbedtls_saber_make_public(mbedtls_saber_context *ctx, size_t *olen,
	unsigned char *buf, size_t blen,
	int(*f_rng)(void *, unsigned char *, size_t),
	void *p_rng);

/**
* Reads a TLS ClientKeyExchange payload.
*/
int mbedtls_saber_read_public(mbedtls_saber_context *ctx,
	const unsigned char *buf, size_t blen);

/**
* This function derives and exports the shared secret.
*/
int mbedtls_saber_calc_secret(mbedtls_saber_context *ctx, size_t *olen,
	unsigned char *buf, size_t blen);

int mbedtls_saber_genkey(mbedtls_saber_context *ctx,
	int(*f_rng)(void *, unsigned char *, size_t), void *p_rng);

int mbedtls_saber_enc(mbedtls_saber_context *ctx,
	int(*f_rng)(void *, unsigned char *, size_t), void *p_rng);

int mbedtls_saber_dec(mbedtls_saber_context *ctx);

int mbedtls_saber_check_pub_priv(const mbedtls_saber_context *pub, const mbedtls_saber_context *prv);

void mbedtls_saber_init(mbedtls_saber_context *ctx);

void mbedtls_saber_free(mbedtls_saber_context *ctx);

#endif /* api_h */
