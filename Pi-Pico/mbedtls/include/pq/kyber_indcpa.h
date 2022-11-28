#ifndef INDCPA_H
#define INDCPA_H

void indcpa_keypair(unsigned char *pk, 
                   unsigned char *sk,
				   int(*f_rng)(void *, unsigned char *, size_t), 
	               void *p_rng);

void indcpa_enc(unsigned char *c,
               const unsigned char *m,
               const unsigned char *pk,
               const unsigned char *coins);

void indcpa_dec(unsigned char *m,
               const unsigned char *c,
               const unsigned char *sk);

#endif
