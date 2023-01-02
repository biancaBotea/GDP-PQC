# Install script for directory: /home/ubuntu/Documents/GDP/mbedtls/include

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/mbedtls" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/aes.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/aesni.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/arc4.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/aria.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/asn1.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/asn1write.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/base64.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/bignum.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/blowfish.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/bn_mul.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/build_info.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/camellia.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/ccm.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/certs.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/chacha20.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/chachapoly.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/check_config.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/cipher.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/cipher_internal.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/cmac.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/compat-1.3.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/config.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/config_psa.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/constant_time.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/ctr_drbg.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/debug.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/des.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/dhm.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/ecdh.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/ecdsa.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/ecjpake.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/ecp.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/ecp_internal.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/entropy.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/entropy_poll.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/error.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/gcm.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/havege.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/hkdf.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/hmac_drbg.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/legacy_or_psa.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/mbedtls_config.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/md.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/md2.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/md4.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/md5.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/md_internal.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/memory_buffer_alloc.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/net.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/net_sockets.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/nist_kw.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/oid.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/padlock.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/pem.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/pk.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/pk_internal.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/pkcs11.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/pkcs12.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/pkcs5.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/platform.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/platform_time.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/platform_util.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/poly1305.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/psa_util.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/ripemd160.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/rsa 2.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/rsa.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/rsa_internal 2.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/rsa_internal.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/sha1 2.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/sha1.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/sha256 2.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/sha256.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/sha512 2.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/sha512.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/shake256.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/ssl 2.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/ssl.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/ssl_cache 2.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/ssl_cache.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/ssl_ciphersuites 2.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/ssl_ciphersuites.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/ssl_cookie 2.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/ssl_cookie.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/ssl_internal 2.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/ssl_internal.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/ssl_ticket 2.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/ssl_ticket.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/threading 2.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/threading.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/timing 2.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/timing.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/version 2.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/version.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/x509 2.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/x509.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/x509_crl 2.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/x509_crl.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/x509_crt 2.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/x509_crt.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/x509_csr 2.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/x509_csr.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/xtea 2.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/mbedtls/xtea.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/pq" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/aes256ctr.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/dilithium.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/dilithium_api.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/dilithium_fips202.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/dilithium_ntt.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/dilithium_packing.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/dilithium_params.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/dilithium_poly.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/dilithium_polyvec.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/dilithium_reduce.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/dilithium_rng.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/dilithium_rounding.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/dilithium_symmetric.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/fips202.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/kyber.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/kyber_cbd.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/kyber_indcpa.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/kyber_ntt.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/kyber_params.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/kyber_poly.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/kyber_polyvec.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/kyber_reduce.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/kyber_verify.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/spx.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/spx_fors.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/spx_hash.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/spx_hash_address.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/spx_params.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/spx_utils.h"
    "/home/ubuntu/Documents/GDP/mbedtls/include/pq/spx_wots.h"
    )
endif()

