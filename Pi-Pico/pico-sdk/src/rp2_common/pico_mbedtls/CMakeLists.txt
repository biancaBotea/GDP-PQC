if (PICO_MBEDTLS_PATH)
    message("Using PICO_MBEDTLS_PATH ('${PICO_MBEDTLS_PATH}')")
elseif (DEFINED ENV{PICO_MBEDTLS_PATH} AND (NOT PICO_MBEDTLS_PATH))
    set(PICO_MBEDTLS_PATH $ENV{PICO_MBEDTLS_PATH})
    message("Using PICO_MBEDTLS_PATH from environment ('${PICO_MBEDTLS_PATH}')")
endif()

if (PICO_MBEDTLS_PATH)

    set(src_crypto
		aes.c
	    aes256ctr.c
	    aesni.c
	    arc4.c
	    aria.c
	    asn1parse.c
	    asn1write.c
	    base64.c
	    bignum.c
	    blowfish.c
	    camellia.c
	    ccm.c
	    chacha20.c
	    chachapoly.c
	    cipher.c
	    cipher_wrap.c
	    cmac.c
	    ctr_drbg.c
	    des.c
	    dhm.c
	    dilithium.c
	    dilithium_ntt.c
	    dilithium_packing.c
	    dilithium_poly.c
	    dilithium_polyvec.c
	    dilithium_reduce.c
	    dilithium_rounding.c
	    dilithium_symmetric-aes.c
	    dilithium_symmetric-shake.c
	    dilithium_fips202.c
	    fips202.c
	    ecdh.c
	    ecdsa.c
	    ecjpake.c
	    ecp.c
	    ecp_curves.c
	    entropy.c
	    entropy_poll.c
	    error.c
	    gcm.c
	    havege.c
	    hkdf.c
	    hmac_drbg.c
	    kyber_cbd.c
	    kyber_indcpa.c
	    kyber_kem.c
	    kyber_ntt.c
	    kyber_poly.c
	    kyber_polyvec.c
	    kyber_precomp.c
	    kyber_reduce.c
	    kyber_verify.c
	    md.c
	    md2.c
	    md4.c
	    md5.c
	    md_wrap.c
	    memory_buffer_alloc.c
	    nist_kw.c
	    oid.c
	    padlock.c
	    pem.c
	    pk.c
	    pk_wrap.c
	    pkcs12.c
	    pkcs5.c
	    pkparse.c
	    pkwrite.c
	    platform.c
	    platform_util.c
	    poly1305.c
	    ripemd160.c
	    rsa.c
	    rsa_internal.c
	    sha1.c
	    sha256.c
	    sha512.c
	    shake256.c
	    spx.c
	    spx_fors.c
	    spx_hash_address.c
	    spx_hash_sha256.c
	    spx_hash_shake256.c
	    spx_utils.c
	    spx_wots.c
	    threading.c
	    timing.c
	    version.c
	    version_features.c
	    xtea.c
    )
    
    set(src_ssl
		dilithium_rng.c
	)

    set(src_x509
        certs.c
		pkcs11.c
		x509.c
		x509_create.c
		x509_crl.c
		x509_crt.c
		x509_csr.c
		x509write_crt.c
		x509write_csr.c
    )

    set(src_tls
        debug.c
		net_sockets.c
		ssl_cache.c
		ssl_ciphersuites.c
		ssl_cli.c
		ssl_cookie.c
		ssl_srv.c
		ssl_ticket.c
		ssl_tls.c
    )
    
    set(MBEDTLS_SRC "")
    foreach(FILE IN LISTS src_crypto src_x509 src_tls)
        list(APPEND MBEDTLS_SRC ${PICO_MBEDTLS_PATH}/library/${FILE})
    endforeach()

    add_library(pico_mbedtls INTERFACE)
    target_sources(pico_mbedtls INTERFACE ${MBEDTLS_SRC})
    target_compile_definitions(pico_mbedtls INTERFACE MBEDTLS_CONFIG_FILE="mbedtls_config.h")
    target_include_directories(pico_mbedtls INTERFACE ${PICO_MBEDTLS_PATH}/include/ ${PICO_MBEDTLS_PATH}/library/)

endif()

