/* Workaround for some mbedtls source files using INT_MAX without including limits.h */
#include <limits.h>

#define MBEDTLS_USER_CONFIG_FILE

#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_HARDWARE_ALT

#define MBEDTLS_SSL_OUT_CONTENT_LEN    2048

#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#define MBEDTLS_HAVE_TIME

#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_ECP_DP_SECP192R1_ENABLED
#define MBEDTLS_ECP_DP_SECP224R1_ENABLED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_SECP521R1_ENABLED
#define MBEDTLS_ECP_DP_SECP192K1_ENABLED
#define MBEDTLS_ECP_DP_SECP224K1_ENABLED
#define MBEDTLS_ECP_DP_SECP256K1_ENABLED
#define MBEDTLS_ECP_DP_BP256R1_ENABLED
#define MBEDTLS_ECP_DP_BP384R1_ENABLED
#define MBEDTLS_ECP_DP_BP512R1_ENABLED
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
//#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_SHA256_SMALLER
#define MBEDTLS_SSL_SERVER_NAME_INDICATION
#define MBEDTLS_AES_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_ERROR_C
#define MBEDTLS_MD_C
#define MBEDTLS_MD5_C
#define MBEDTLS_OID_C
#define MBEDTLS_PKCS5_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PLATFORM_C
//#define MBEDTLS_RSA_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_SSL_CLI_C
//#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_AES_FEWER_TABLES

/* TLS 1.2 */
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_GCM_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ASN1_WRITE_C

/* Additional required configuration */
#define MBEDTLS_CERTS_C
#undef MBEDTLS_FS_IO
#define MBEDTLS_TEST_SHAKE256
#define MBEDTLS_HAVE_TIME_DATE
#define MBEDTLS_SHAKE256_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_XTEA_C
#define MBEDTLS_BASE64_C

/* PQC */
#define MBEDTLS_KYBER_C
#define MBEDTLS_KEY_EXCHANGE_KYBER_ECDSA_ENABLED
/* PQC-SPHINCS */
#define MBEDTLS_SPHINCS_C
#define MBEDTLS_SPHINCS_MAX_SIZE 20000
#define MBEDTLS_SSL_SPHINCS
#define MBEDTLS_KEY_EXCHANGE_ECDHE_SPHINCS_ENABLED
#define MBEDTLS_KEY_EXCHANGE_KYBER_SPHINCS_ENABLED
#define MBEDTLS_SSL_HS_FRAGMENTATION
#define MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
/* PQC-DILITHIUM */
#define MBEDTLS_DILITHIUM_C
#define MBEDTLS_SSL_DILITHIUM
#define MBEDTLS_KEY_EXCHANGE_ECDHE_DILITHIUM_ENABLED
#define MBEDTLS_KEY_EXCHANGE_KYBER_DILITHIUM_ENABLED
/* PQC-SABER */
#define MBEDTLS_SABER_C
#define MBEDTLS_KEY_EXCHANGE_SABER_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_SABER_SPHINCS_ENABLED
#define MBEDTLS_KEY_EXCHANGE_SABER_DILITHIUM_ENABLED

//#define MBEDTLS_PICO_LATENCY
//#define MBEDTLS_PICO_CYCLES
