#ifndef PARAMS_D_H
#define PARAMS_D_H

// #include "mbedtls/config.h"

#ifndef DILITHIUM_MODE
#define DILITHIUM_MODE 2 /* Change this for different security strengths */
#endif

#define SEEDBYTES_D 32
#define CRHBYTES 64
#define N_D 256
#define Q_D 8380417
#define D_D 13
#define ROOT_OF_UNITY 1753

#if DILITHIUM_MODE == 2
#define K_D 4
#define L_D 4
#define ETA 2
#define TAU 39
#define BETA 78
#define GAMMA1 (1 << 17)
#define GAMMA2 ((Q_D-1)/88)
#define OMEGA 80

#elif DILITHIUM_MODE == 3
#define K_D 6
#define L_D 5
#define ETA 4
#define TAU 49
#define BETA 196
#define GAMMA1 (1 << 19)
#define GAMMA2 ((Q_D-1)/32)
#define OMEGA 55

#elif DILITHIUM_MODE == 5
#define K_D 8
#define L_D 7
#define ETA 2
#define TAU 60
#define BETA 120
#define GAMMA1 (1 << 19)
#define GAMMA2 ((Q_D-1)/32)
#define OMEGA 75

#endif

#define POLYT1_PACKEDBYTES  320
#define POLYT0_PACKEDBYTES  416
#define POLYVECH_PACKEDBYTES (OMEGA + K_D)

#if GAMMA1 == (1 << 17)
#define POLYZ_PACKEDBYTES   576
#elif GAMMA1 == (1 << 19)
#define POLYZ_PACKEDBYTES   640
#endif

#if GAMMA2 == (Q_D-1)/88
#define POLYW1_PACKEDBYTES  192
#elif GAMMA2 == (Q_D-1)/32
#define POLYW1_PACKEDBYTES  128
#endif

#if ETA == 2
#define POLYETA_PACKEDBYTES  96
#elif ETA == 4
#define POLYETA_PACKEDBYTES 128
#endif

#define CRYPTO_PUBLICKEYBYTES_D (SEEDBYTES_D + K_D*POLYT1_PACKEDBYTES)
#define CRYPTO_SECRETKEYBYTES_D (3*SEEDBYTES_D \
                               + L_D*POLYETA_PACKEDBYTES \
                               + K_D*POLYETA_PACKEDBYTES \
                               + K_D*POLYT0_PACKEDBYTES)
#define CRYPTO_BYTES_D (SEEDBYTES_D + L_D*POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES)

#endif
