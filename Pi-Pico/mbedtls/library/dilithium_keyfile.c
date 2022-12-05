#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ASN1_PARSE_C)

#include "mbedtls/asn1.h"
#include "mbedtls/platform_util.h"

#include <string.h>
#include "pq/dilithium_params.h"

int prepare_dilithium_key_formtat ( unsigned char *pk , unsigned char *sk , 
	unsigned char *final_buf){

/*
	* DILITHIUM_key ::= SEQUENCE {
		* SecretKey BIT STRING ,
		* PublicKey BIT STRING
	* }
*/

	unsigned char *buf, *c;
	size_t len = 0;
	size_t *final_buf_bytes_written;
	buf = (unsigned char *) malloc(5000);

	c = buf + 5000;


	// Write keys to buffer in ASN .1 format
	MBEDTLS_ANS1_CHK_ADD(len, mbedtls_asn1_write_bitstring(&c, buf, pk, 
		CRYPTO_PUBLICKEYBYTES_D * 8));
	MBEDTLS_ANS1_CHK_ADD(len, mbedtls_asn1_write_bitstring(&c, buf, sk, 
		CRYPTO_SECRETKEYBYTES_D * 8));
	MBEDTLS_ANS1_CHK_ADD(len, mbedtls_asn1_write_bitstring(&c, buf, len));
	MBEDTLS_ANS1_CHK_ADD(len, mbedtls_asn1_write_bitstring(&c, buf, 
		MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ));

	//Base64 encoding the written buffer
	size_t final_buf_size = 4*(len / 3 + (len % 3 != 0));
	final_buf_bytes_written = (size_t *) malloc(16);
	mbedtls_base64_encoding(final_buf, final_buf_size + 1, 
		final_buf_bytes_written, buf, len);

	//Reutrn num of bytes in buffer
	return final_buf_bytes_written;
}