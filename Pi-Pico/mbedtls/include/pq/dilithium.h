#ifndef DILITHIUM_H
#define DILITHIUM_H

#include <stddef.h>
#include <stdint.h>
#include "pq/dilithium_params.h"
#include "pq/dilithium_poly.h"
#include "pq/dilithium_polyvec.h"
#include "mbedtls/md.h"


typedef struct mbedtls_dilithium_context
{
	unsigned char pk[CRYPTO_PUBLICKEYBYTES_D];
	unsigned char sk[CRYPTO_SECRETKEYBYTES_D];
}mbedtls_dilithium_context;


/*
* Initialize context
*/
void mbedtls_dilithium_init(mbedtls_dilithium_context *ctx);

/*
* Free context
*/
void mbedtls_dilithium_free(mbedtls_dilithium_context *ctx);

/**
 * \brief          This function retrieves the length of dilithium modulus in Bytes.
 *
 * \param ctx      The initialized dilithium context.
 *
 * \return         The length of the dilithium modulus in Bytes.
 *
 */
size_t mbedtls_dilithium_get_len( const mbedtls_dilithium_context *ctx );

/**
* \brief           This function computes the dilithium+ signature and writes it
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
	int(*f_rng)(void *, unsigned char *, size_t), void *p_rng
	);

/**
* \brief           This function reads and verifies an dilithium+ signature.
*
* \param ctx       The dilithium context.
* \param hash      The message hash.
* \param hlen      The size of the hash.
* \param sig       The signature to read and verify.
* \param slen      The size of \p sig.
*
* \return          \c 0 on success
*					or an error code on failure.
*/
int mbedtls_dilithium_read_signature(mbedtls_dilithium_context *ctx,
	//mbedtls_md_type_t md_alg,
	const unsigned char *hash, size_t hlen,
	const unsigned char *sig, size_t slen);



//#define challenge DILITHIUM_NAMESPACE(challenge)
void challenge(poly *c, const unsigned char seed[SEEDBYTES_D]);

//#define crypto_sign_keypair DILITHIUM_NAMESPACE(keypair)
int crypto_sign_keypair_d(unsigned char *pk, unsigned char *sk,
      int(*f_rng)(void *, unsigned char *, size_t), void *p_rng);

//#define crypto_sign_signature DILITHIUM_NAMESPACE(signature)
int crypto_sign_signature_d(unsigned char *sig, size_t *siglen,
                          const unsigned char *m, size_t mlen,
                          const unsigned char *sk);

//#define crypto_sign DILITHIUM_NAMESPACETOP
int crypto_sign_d(unsigned char *sm, size_t *smlen,
                const unsigned char *m, size_t mlen,
                const unsigned char *sk);

//#define crypto_sign_verify DILITHIUM_NAMESPACE(verify)
int crypto_sign_verify_d(const unsigned char *sig, size_t siglen,
                       const unsigned char *m, size_t mlen,
                       const unsigned char *pk);

//#define crypto_sign_open DILITHIUM_NAMESPACE(open)
int crypto_sign_open_d(unsigned char *m, size_t *mlen,
                     const unsigned char *sm, size_t smlen,
                     const unsigned char *pk);

#endif
