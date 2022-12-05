#ifndef API_H
#define API_H
#include <stddef.h>
#include <stdint.h>

#define pqcrystals_dilithium2_PUBL_DICK_DEYBYTES 1312
#define pqcrystals_dilithium2_SECRETK_DEYBYTES 2528
#define pqcrystals_dilithium2_BYTES 2420

#define pqcrystals_dilithium2_ref_PUBL_DICK_DEYBYTES pqcrystals_dilithium2_PUBL_DICK_DEYBYTES
#define pqcrystals_dilithium2_ref_SECRETK_DEYBYTES pqcrystals_dilithium2_SECRETK_DEYBYTES
#define pqcrystals_dilithium2_ref_BYTES pqcrystals_dilithium2_BYTES

int pqcrystals_dilithium2_ref_keypair(unsigned char *pk, unsigned char *sk);

int pqcrystals_dilithium2_ref_signature(unsigned char *sig, size_t *siglen,
                                        const unsigned char *m, size_t mlen,
                                        const unsigned char *sk);

int pqcrystals_dilithium2_ref(unsigned char *sm, size_t *smlen,
                              const unsigned char *m, size_t mlen,
                              const unsigned char *sk);

int pqcrystals_dilithium2_ref_verify(const unsigned char *sig, size_t siglen,
                                     const unsigned char *m, size_t mlen,
                                     const unsigned char *pk);

int pqcrystals_dilithium2_ref_open(unsigned char *m, size_t *mlen,
                                   const unsigned char *sm, size_t smlen,
                                   const unsigned char *pk);

#define pqcrystals_dilithium2aes_ref_PUBL_DICK_DEYBYTES pqcrystals_dilithium2_ref_PUBL_DICK_DEYBYTES
#define pqcrystals_dilithium2aes_ref_SECRETK_DEYBYTES pqcrystals_dilithium2_ref_SECRETK_DEYBYTES
#define pqcrystals_dilithium2aes_ref_BYTES pqcrystals_dilithium2_ref_BYTES

int pqcrystals_dilithium2aes_ref_keypair(unsigned char *pk, unsigned char *sk);

int pqcrystals_dilithium2aes_ref_signature(unsigned char *sig, size_t *siglen,
                                           const unsigned char *m, size_t mlen,
                                           const unsigned char *sk);

int pqcrystals_dilithium2aes_ref(unsigned char *sm, size_t *smlen,
                                 const unsigned char *m, size_t mlen,
                                 const unsigned char *sk);

int pqcrystals_dilithium2aes_ref_verify(const unsigned char *sig, size_t siglen,
                                        const unsigned char *m, size_t mlen,
                                        const unsigned char *pk);

int pqcrystals_dilithium2aes_ref_open(unsigned char *m, size_t *mlen,
                                      const unsigned char *sm, size_t smlen,
                                      const unsigned char *pk);

#define pqcrystals_dilithium3_PUBL_DICK_DEYBYTES 1952
#define pqcrystals_dilithium3_SECRETK_DEYBYTES 4000
#define pqcrystals_dilithium3_BYTES 3293

#define pqcrystals_dilithium3_ref_PUBL_DICK_DEYBYTES pqcrystals_dilithium3_PUBL_DICK_DEYBYTES
#define pqcrystals_dilithium3_ref_SECRETK_DEYBYTES pqcrystals_dilithium3_SECRETK_DEYBYTES
#define pqcrystals_dilithium3_ref_BYTES pqcrystals_dilithium3_BYTES

int pqcrystals_dilithium3_ref_keypair(unsigned char *pk, unsigned char *sk);

int pqcrystals_dilithium3_ref_signature(unsigned char *sig, size_t *siglen,
                                        const unsigned char *m, size_t mlen,
                                        const unsigned char *sk);

int pqcrystals_dilithium3_ref(unsigned char *sm, size_t *smlen,
                              const unsigned char *m, size_t mlen,
                              const unsigned char *sk);

int pqcrystals_dilithium3_ref_verify(const unsigned char *sig, size_t siglen,
                                     const unsigned char *m, size_t mlen,
                                     const unsigned char *pk);

int pqcrystals_dilithium3_ref_open(unsigned char *m, size_t *mlen,
                                   const unsigned char *sm, size_t smlen,
                                   const unsigned char *pk);

#define pqcrystals_dilithium3aes_ref_PUBL_DICK_DEYBYTES pqcrystals_dilithium3_ref_PUBL_DICK_DEYBYTES
#define pqcrystals_dilithium3aes_ref_SECRETK_DEYBYTES pqcrystals_dilithium3_ref_SECRETK_DEYBYTES
#define pqcrystals_dilithium3aes_ref_BYTES pqcrystals_dilithium3_ref_BYTES

int pqcrystals_dilithium3aes_ref_keypair(unsigned char *pk, unsigned char *sk);

int pqcrystals_dilithium3aes_ref_signature(unsigned char *sig, size_t *siglen,
                                           const unsigned char *m, size_t mlen,
                                           const unsigned char *sk);

int pqcrystals_dilithium3aes_ref(unsigned char *sm, size_t *smlen,
                                 const unsigned char *m, size_t mlen,
                                 const unsigned char *sk);

int pqcrystals_dilithium3aes_ref_verify(const unsigned char *sig, size_t siglen,
                                        const unsigned char *m, size_t mlen,
                                        const unsigned char *pk);

int pqcrystals_dilithium3aes_ref_open(unsigned char *m, size_t *mlen,
                                      const unsigned char *sm, size_t smlen,
                                      const unsigned char *pk);

#define pqcrystals_dilithium5_PUBL_DICK_DEYBYTES 2592
#define pqcrystals_dilithium5_SECRETK_DEYBYTES 4864
#define pqcrystals_dilithium5_BYTES 4595

#define pqcrystals_dilithium5_ref_PUBL_DICK_DEYBYTES pqcrystals_dilithium5_PUBL_DICK_DEYBYTES
#define pqcrystals_dilithium5_ref_SECRETK_DEYBYTES pqcrystals_dilithium5_SECRETK_DEYBYTES
#define pqcrystals_dilithium5_ref_BYTES pqcrystals_dilithium5_BYTES

int pqcrystals_dilithium5_ref_keypair(unsigned char *pk, unsigned char *sk);

int pqcrystals_dilithium5_ref_signature(unsigned char *sig, size_t *siglen,
                                        const unsigned char *m, size_t mlen,
                                        const unsigned char *sk);

int pqcrystals_dilithium5_ref(unsigned char *sm, size_t *smlen,
                              const unsigned char *m, size_t mlen,
                              const unsigned char *sk);

int pqcrystals_dilithium5_ref_verify(const unsigned char *sig, size_t siglen,
                                     const unsigned char *m, size_t mlen,
                                     const unsigned char *pk);

int pqcrystals_dilithium5_ref_open(unsigned char *m, size_t *mlen,
                                   const unsigned char *sm, size_t smlen,
                                   const unsigned char *pk);

#define pqcrystals_dilithium5aes_ref_PUBL_DICK_DEYBYTES pqcrystals_dilithium5_ref_PUBL_DICK_DEYBYTES
#define pqcrystals_dilithium5aes_ref_SECRETK_DEYBYTES pqcrystals_dilithium5_ref_SECRETK_DEYBYTES
#define pqcrystals_dilithium5aes_ref_BYTES pqcrystals_dilithium5_ref_BYTES

int pqcrystals_dilithium5aes_ref_keypair(unsigned char *pk, unsigned char *sk);

int pqcrystals_dilithium5aes_ref_signature(unsigned char *sig, size_t *siglen,
                                           const unsigned char *m, size_t mlen,
                                           const unsigned char *sk);

int pqcrystals_dilithium5aes_ref(unsigned char *sm, size_t *smlen,
                                 const unsigned char *m, size_t mlen,
                                 const unsigned char *sk);

int pqcrystals_dilithium5aes_ref_verify(const unsigned char *sig, size_t siglen,
                                        const unsigned char *m, size_t mlen,
                                        const unsigned char *pk);

int pqcrystals_dilithium5aes_ref_open(unsigned char *m, size_t *mlen,
                                      const unsigned char *sm, size_t smlen,
                                      const unsigned char *pk);


#endif
