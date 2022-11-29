#ifndef INDCPA_H
#define INDCPA_H

void indcpa_keypair(unsigned char *pk, 
	unsigned char *sk, 
	int(*f_rng)(void *, unsigned char *, size_t), 
	void *p_rng);

void indcpa_client(unsigned char *pk, 
	unsigned char *b_prime, 
	unsigned char *c, 
	unsigned char *key);

void indcpa_server(unsigned char *pk, 
	unsigned char *b_prime, 
	unsigned char *c, 
	unsigned char *key);

void indcpa_kem_keypair(unsigned char *pk, 
	unsigned char *sk, 
	int(*f_rng)(void *, unsigned char *, size_t), 
	void *p_rng);

void indcpa_kem_enc(const unsigned char *message, 
	const unsigned char *noiseseed, 
	const unsigned char *pk,  
	unsigned char *ciphertext);

void indcpa_kem_dec(const unsigned char *sk, 
	const unsigned char *ciphertext, 
	unsigned char message_dec[]);


uint64_t clock1,clock2;
uint64_t clock_kp_mv,clock_cl_mv, clock_kp_sm, clock_cl_sm;


#endif

