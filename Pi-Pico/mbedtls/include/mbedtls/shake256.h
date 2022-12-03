#ifndef MBEDTLS_SHAKE256_H
#define MBEDTLS_SHAKE256_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#include "pq/fips202.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mbedtls_shake256_context
{
	
	keccak_state state;				/*!< The intermediate digest state. */
	unsigned char buffer[136];  			/*!< The data block being processed. */
	uint32_t buffer_len[2];          	/*!< The number of Bytes processed. */  

}mbedtls_shake256_context;

/**
 * \brief          This function initializes a SHAKE-256 context.
 *
 * \param ctx      The SHAKE-256 context to initialize. This must
 *                 not be \c NULL.
 */
void mbedtls_shake256_init( mbedtls_shake256_context *ctx );

/**
 * \brief          This function clears a SHAKE-256 context.
 *
 * \param ctx      The SHAKE-256 context to clear. This may be \c NULL,
 *                 in which case this function does nothing. If it
 *                 is not \c NULL, it must point to an initialized
 *                 SHAKE-256 context.
 */
void mbedtls_shake256_free( mbedtls_shake256_context *ctx );

/**
 * \brief          This function starts a SHA-384 or SHAKE-256 checksum
 *                 calculation.
 *
 * \param ctx      The SHAKE-256 context to use. This must be initialized.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_shake256_starts_ret( mbedtls_shake256_context *ctx);

/**
 * \brief          This function feeds an input buffer into an ongoing
 *                 SHAKE-256 checksum calculation.
 *
 * \param ctx      The SHAKE-256 context. This must be initialized
 *                 and have a hash operation started.
 * \param input    The buffer holding the input data. This must
 *                 be a readable buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_shake256_update_ret( mbedtls_shake256_context *ctx,
                    const unsigned char *input,
                    size_t ilen );

/**
 * \brief          This function finishes the SHAKE-256 operation, and writes
 *                 the result to the output buffer. This function is for
 *                 internal use only.
 *
 * \param ctx      The SHAKE-256 context. This must be initialized
 *                 and have a hash operation started.
 * \param output   The SHA-384 or SHAKE-256 checksum result.
 *                 This must be a writable buffer of length \c 64 Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_shake256_finish_ret( mbedtls_shake256_context *ctx,
                               unsigned char output[64] );

/**
 * \brief          This function calculates the SHAKE-256 or SHA-384
 *                 checksum of a buffer.
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The SHAKE-256 result is calculated as
 *                 output = SHAKE-256(input buffer).
 *
 * \param input    The buffer holding the input data. This must be
 *                 a readable buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 * \param output   The SHA-384 or SHAKE-256 checksum result.
 *                 This must be a writable buffer of length \c 64 Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_shake256_ret( const unsigned char *input,
                        size_t ilen,
                        unsigned char output[64]);