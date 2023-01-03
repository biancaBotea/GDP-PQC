#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#define mbedtls_snprintf   snprintf
#endif

#include <string.h>
#include <stdint.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "pq/spx.h"


#define SPX_MLEN 32
#define SPX_SIGNATURES 1

int main()
{
	int ret = 0;
	int i;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	const char *pers = "sphincs_sign";
	
	mbedtls_pk_context ctx_sign;
	unsigned char *m = (unsigned char *)mbedtls_calloc(SPX_MLEN, sizeof(unsigned char));
	//unsigned char *m = malloc(SPX_MLEN);
	unsigned char *sm = (unsigned char *)mbedtls_calloc(SPX_BYTES + SPX_MLEN, sizeof(unsigned char));
	//unsigned char *sm = malloc(SPX_BYTES + SPX_MLEN);
	size_t smlen;
	size_t mlen = SPX_MLEN;

	mbedtls_pk_init(&ctx_sign);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);


	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		(const unsigned char *)pers,
		strlen(pers))) != 0)
	{
		mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret);
		goto exit;
	}

	if ((ret = mbedtls_pk_setup(&ctx_sign, mbedtls_pk_info_from_type(MBEDTLS_PK_SPHINCS))) != 0)
	{
		mbedtls_printf(" failed\n  !  mbedtls_pk_setup returned -0x%04x", -ret);
		goto exit;
	}

	mbedtls_ctr_drbg_random(&ctr_drbg, m, mlen);
	//randombytes(m, mlen);

	printf("Generating keypair.. ");

	if ((ret = mbedtls_sphincs_genkey(MBEDTLS_MD_SHA256, mbedtls_pk_sphincs(ctx_sign), mbedtls_ctr_drbg_random, &ctr_drbg))
		!=0) 
	{
		mbedtls_printf("failed!\n");
		goto exit;
	}
	printf("successful.\n");


	printf("Testing %d signatures.. \n", SPX_SIGNATURES);

	for (i = 0; i < SPX_SIGNATURES; i++) {
		printf("  - iteration #%d:\n", i);

		//crypto_sign(sm, &smlen, m, SPX_MLEN, sk);
		mbedtls_sphincs_write_signature(mbedtls_pk_sphincs(ctx_sign), m, SPX_MLEN, sm, &smlen, mbedtls_ctr_drbg_random, &ctr_drbg);

		if (smlen != SPX_BYTES + SPX_MLEN) {
			printf("  X smlen incorrect [%d != %u]!\n",
				smlen, SPX_BYTES);
			ret = -1;
			goto exit;
		}
		else {
			printf("    smlen as expected [%d].\n", smlen);
		}

		/* Test if signature is valid. */
		//if (crypto_sign_open(mout, &mlen, sm, smlen, pk)) {
		if (mbedtls_sphincs_read_signature(mbedtls_pk_sphincs(ctx_sign), m, SPX_MLEN, sm, smlen)) {
			printf("  X verification failed!\n");
			ret = -1;
			goto exit;
		}
		else {
			printf("    verification succeeded.\n");
		}

		/* Test if flipping bits invalidates the signature (it should). */

		/* Flip the first bit of the message. Should invalidate. */
		m[0] ^= 1;
		//if (!crypto_sign_open(mout, &mlen, sm, smlen, pk)) {
		if (!mbedtls_sphincs_read_signature(mbedtls_pk_sphincs(ctx_sign), m, SPX_MLEN, sm, smlen)) {
			printf("  X flipping a bit of m DID NOT invalidate signature!\n");
			ret = -1;
			goto exit;
		}
		else {
			printf("    flipping a bit of m invalidates signature.\n");
		}
	}

	mbedtls_free(m);
	mbedtls_free(sm);

exit:
	return (ret);
}

