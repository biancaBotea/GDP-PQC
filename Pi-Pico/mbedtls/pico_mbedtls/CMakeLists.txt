if (DEFINED ENV{PICO_MBEDTLS_PATH} AND (NOT PICO_MBEDTLS_PATH))
    set(PICO_MBEDTLS_PATH $ENV{PICO_MBEDTLS_PATH})
    message("Using PICO_MBEDTLS_PATH from environment ('${PICO_MBEDTLS_PATH}')")
endif()

set(MBEDTLS_TEST_PATH "library/aes.c")
if (NOT PICO_MBEDTLS_PATH)
    set(PICO_MBEDTLS_PATH ${PROJECT_SOURCE_DIR}/lib/mbedtls)
elseif (NOT EXISTS ${PICO_MBEDTLS_PATH}/${MBEDTLS_TEST_PATH})
    message(WARNING "PICO_MBEDTLS_PATH specified but content not present.")
endif()

if (EXISTS ${PICO_MBEDTLS_PATH}/${MBEDTLS_TEST_PATH})
    message("mbedtls available at ${PICO_MBEDTLS_PATH}")

    pico_register_common_scope_var(PICO_MBEDTLS_PATH)

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
        certs.c
        chacha20.c
        chachapoly.c
        cipher.c
        cipher_wrap.c
        cmac.c
        #constant_time.c
        ctr_drbg.c
        des.c
        dhm.c
        dilithium.c
        dilithium_ntt.c
        dilithium_packing.c
        dilithium_poly.c
        dilithium_polyvec.c
        dilithium_reduce.c
        dilithium_rng.c
        dilithium_rounding.c
        dilithium_symmetric-aes.c
        dilithium_symmetric-shake.c
        ecdh.c
        ecdsa.c
        ecjpake.c
        ecp.c
        ecp_curves.c
        ecp_invasive.h
        entropy.c
        entropy_poll.c
        error.c
        fips202.c
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
        #mps_reader.c
        #mps_trace.c
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
        poly_mul.c
        #psa_crypto.c
        #psa_crypto_aead.c
        #psa_crypto_cipher.c
        #psa_crypto_client.c
        #psa_crypto_driver_wrappers.c
        #psa_crypto_ecp.c
        #psa_crypto_hash.c
        #psa_crypto_mac.c
        #psa_crypto_rsa.c
        #psa_crypto_se.c
        #psa_crypto_slot_management.c
        #psa_crypto_storage.c
        #psa_its_file.c
        recon_FireSaber.c
        recon_LightSaber.c
        recon_Saber.c
        ripemd160.c
        rsa.c
        rsa_internal.c
        #saber_cbd.c
        #saber_indcpa.c
        #saber_kem.c
        #saber_pack_unpack.c
        #saber_poly.c
        #saber_recon.c
        #saber_rng.c
        #saber_verify.c
        sha1.c
        sha256.c
        sha512.c
        shake256.c
        spx.c
        spx_fors.c
        spx_hash_address.c
        spx_hash_sha256.c
        spx_hash_sahke256.c
        spx_utils.c
        spx_wots.c
        threading.c
        timing.c
        version.c
        version_features.c
        xtea.c
    )
    list(TRANSFORM src_crypto PREPEND ${PICO_MBEDTLS_PATH}/library/)
    add_library(pico_mbedtls_crypto INTERFACE)
    target_sources(pico_mbedtls_crypto INTERFACE ${src_crypto})

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
    list(TRANSFORM src_x509 PREPEND ${PICO_MBEDTLS_PATH}/library/)
    add_library(pico_mbedtls_x509 INTERFACE)
    target_sources(pico_mbedtls_x509 INTERFACE ${src_x509})

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
        #ssl_tls13_keys.c
    )
    list(TRANSFORM src_tls PREPEND ${PICO_MBEDTLS_PATH}/library/)
    add_library(pico_mbedtls_tls INTERFACE)
    target_sources(pico_mbedtls_tls INTERFACE ${src_tls})

    pico_add_impl_library(pico_mbedtls)
    target_link_libraries(pico_mbedtls INTERFACE pico_mbedtls_crypto pico_mbedtls_x509 pico_mbedtls_tls)
    if (DEFINED PICO_MBEDTLS_CONFIG_FILE)
        target_compile_definitions(pico_mbedtls INTERFACE MBEDTLS_CONFIG_FILE="${PICO_MBEDTLS_CONFIG_FILE}")
    else()
        target_compile_definitions(pico_mbedtls INTERFACE MBEDTLS_CONFIG_FILE="mbedtls_config.h")
    endif()
    target_include_directories(pico_mbedtls INTERFACE ${PICO_MBEDTLS_PATH}/include/ ${PICO_MBEDTLS_PATH}/library/)

    function(suppress_mbedtls_warnings)
        set_source_files_properties(
            ${PICO_MBEDTLS_PATH}/library/ecdsa.c
            ${PICO_MBEDTLS_PATH}/library/ecp.c
            ${PICO_MBEDTLS_PATH}/library/ecp_curves.c
            ${PICO_MBEDTLS_PATH}/library/pk_wrap.c
            ${PICO_MBEDTLS_PATH}/library/pkparse.c
            ${PICO_MBEDTLS_PATH}/library/ssl_cli.c
            PROPERTIES
            COMPILE_OPTIONS "-Wno-cast-qual"
        )
        set_source_files_properties(
            ${PICO_MBEDTLS_PATH}/library/psa_crypto_client.c
            ${PICO_MBEDTLS_PATH}/library/psa_crypto_driver_wrappers.c
            PROPERTIES
            COMPILE_OPTIONS "-Wno-redundant-decls"
        )
        set_source_files_properties(
            ${PICO_MBEDTLS_PATH}/library/x509_crt.c
            PROPERTIES
            COMPILE_OPTIONS "-Wno-cast-qual;-Wno-null-dereference"
        )
        set_source_files_properties(
            ${PICO_MBEDTLS_PATH}/library/ssl_srv.c
            ${PICO_MBEDTLS_PATH}/library/ssl_tls.c
            PROPERTIES
            COMPILE_OPTIONS "-Wno-null-dereference"
        )
    endfunction()

    pico_promote_common_scope_vars()
endif()
