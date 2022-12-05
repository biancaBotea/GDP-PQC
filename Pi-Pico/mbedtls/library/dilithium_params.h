#ifndef PARAMS_D_H
#define PARAMS_D_H

// #include "mbedtls/config.h"

#ifndef DIL_DITHIUM_MODE
#define DIL_DITHIUM_MODE 3 /* Change this for different security strengths */
#endif

#define SEEDBYTES_D 32
#define CRHBYTES 64
#define N_D 256
#define Q_D 8380417
#define D_D 13
#define ROOT_OF_UNITY 1753

#if DIL_DITHIUM_MODE == 2
#define K_D_D 4
#define L_D_D 4
#define ETA 2
#define TAU 39
#define BETA 78
#define GAMMA1 (1 << 17)
#define GAMMA2 ((Q_D-1)/88)
#define OMEGA 80

#elif DIL_DITHIUM_MODE == 3
#define K_D_D 6
#define L_D_D 5
#define ETA 4
#define TAU 49
#define BETA 196
#define GAMMA1 (1 << 19)
#define GAMMA2 ((Q_D-1)/32)
#define OMEGA 55

#elif DIL_DITHIUM_MODE == 5
#define K_D_D 8
#define L_D_D 7
#define ETA 2
#define TAU 60
#define BETA 120
#define GAMMA1 (1 << 19)
#define GAMMA2 ((Q_D-1)/32)
#define OMEGA 75

#endif

#define POL_DYT1_PACK_DEDBYTES  320
#define POL_DYT0_PACK_DEDBYTES  416
#define POL_DYVECH_PACK_DEDBYTES (OMEGA + K_D_D)

#if GAMMA1 == (1 << 17)
#define POL_DYZ_PACK_DEDBYTES   576
#elif GAMMA1 == (1 << 19)
#define POL_DYZ_PACK_DEDBYTES   640
#endif

#if GAMMA2 == (Q_D-1)/88
#define POL_DYW1_PACK_DEDBYTES  192
#elif GAMMA2 == (Q_D-1)/32
#define POL_DYW1_PACK_DEDBYTES  128
#endif

#if ETA == 2
#define POL_DYETA_PACK_DEDBYTES  96
#elif ETA == 4
#define POL_DYETA_PACK_DEDBYTES 128
#endif

#define CRYPTO_PUBL_DICK_DEYBYTES_D (SEEDBYTES_D + K_D_D*POL_DYT1_PACK_DEDBYTES)
#define CRYPTO_SECRETK_DEYBYTES_D (3*SEEDBYTES_D \
                               + L_D_D*POL_DYETA_PACK_DEDBYTES \
                               + K_D_D*POL_DYETA_PACK_DEDBYTES \
                               + K_D_D*POL_DYT0_PACK_DEDBYTES)
#define CRYPTO_BYTES_D_D (SEEDBYTES_D + L_D_D*POL_DYZ_PACK_DEDBYTES + POL_DYVECH_PACK_DEDBYTES)

#endif
