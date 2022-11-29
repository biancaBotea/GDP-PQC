#ifndef INDCPA_H
#define INDCPA_H

/*
* SABER error codes
*/
#define MBEDTLS_ERR_SABER_BAD_INPUT_DATA                    -0x5081  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_SABER_FEATURE_UNAVAILABLE               -0x5082  /**< New Hope key exchange is not available. */
#define MBEDTLS_ERR_SABER_FAILED_TO_GENERATE_RANDOM         -0x5083  /**< Unable to generate sufficient random bytes. */
#define MBEDTLS_ERR_SABER_BUFFER_TOO_SMALL                  -0x5000  /**< The buffer is too small to write to. */

#define CRYPTO_SECRETKEYBYTES  SABER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  SABER_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES SABER_CIPHERTEXTBYTES
#define CRYPTO_BYTES           SABER_SYMBYTES

typedef struct
{
	unsigned int n;
	unsigned int k;
	unsigned int q;
}
mbedtls_saber_params;

typedef struct
{
	mbedtls_mpi sk_poly;
	mbedtls_mpi pk_poly;
	mbedtls_mpi ss;
	mbedtls_mpi ct;
	unsigned char sk_seed[SABER_SYMBYTES];
	unsigned char pk_hash[SABER_SYMBYTES];
	unsigned char pk_seed[SABER_SYMBYTES];
	size_t bitlen;
}
mbedtls_saber_keypair;

typedef struct
{
	mbedtls_saber_params params;
	mbedtls_saber_keypair key;
}
mbedtls_saber_context;

/* Reference Implementation */
void indcpa_keypair(unsigned char *pk, 
	unsigned char *sk, i
	nt(*f_rng)(void *, unsigned char *, size_t), 
	void *p_rng);

void indcpa_client(unsigned char *pk, 
	unsigned char *b_prime,
	unsigned char *c,
	unsigned char *key);

void indcpa_server(unsigned char *pk, 
	unsigned char *b_prime, 
	unsigned char *c,
	unsigned char *key);

void indcpa_kem_keypair(unsigned char *pk, 
	unsigned char *sk, 
	int(*f_rng)(void *, unsigned char *, size_t), 
	void *p_rng);

void indcpa_kem_enc(unsigned char *message, 
	unsigned char *noiseseed, 
	unsigned char *pk,  
	unsigned char *ciphertext);

void indcpa_kem_dec(unsigned char *sk, 
	unsigned char *ciphertext, 
	unsigned char message_dec[]);

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk, 
  int(*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int crypto_kem_enc(unsigned char *c, unsigned char *k, const unsigned char *pk,
  int(*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int crypto_kem_dec(unsigned char *k, const unsigned char *c, const unsigned char *sk);

uint64_t clock1,clock2;
uint64_t clock_kp_mv,clock_cl_mv, clock_kp_sm, clock_cl_sm;

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


#endif
