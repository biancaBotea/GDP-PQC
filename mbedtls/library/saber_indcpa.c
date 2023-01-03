#include <string.h>
#include <stdint.h>
#include "pq/saber_indcpa.h"
#include "pq/saber_poly.h"
#include "pq/saber_pack_unpack.h"
#include "pq/saber_poly_mul.h"
#include "pq/saber_fips202.h"
#include "pq/saber_params.h"

#define h1 (1 << (SABER_EQ - SABER_EP - 1))
#define h2 ((1 << (SABER_EP - 2)) - (1 << (SABER_EP - SABER_ET - 1)) + (1 << (SABER_EQ - SABER_EP - 1)))

/*-----------------------------------------------------------------------------------
	This routine generates a=[Matrix K x K] of 256-coefficient polynomials 
-------------------------------------------------------------------------------------*/

/*void VectorMul(uint16_t pkcl[SABER_K][SABER_N],uint16_t skpv[SABER_K][SABER_N],uint16_t mod,uint16_t res[SABER_N]);
void MatrixVectorMul(polyvec *a, uint16_t skpv[SABER_K][SABER_N], uint16_t res[SABER_K][SABER_N], uint16_t mod, int16_t transpose);

void POL2MSG(uint16_t *message_dec_unpacked, unsigned char *message_dec); */

void indcpa_kem_keypair(uint8_t pk[SABER_INDCPA_PUBLICKEYBYTES], uint8_t sk[SABER_INDCPA_SECRETKEYBYTES], 
				int(*f_rng)(void *, unsigned char *, size_t), 
				void *p_rng)
{
	uint16_t A[SABER_L][SABER_L][SABER_N];
	uint16_t s[SABER_L][SABER_N];
	uint16_t b[SABER_L][SABER_N] = {0};

	uint8_t seed_A[SABER_SEEDBYTES];
	uint8_t seed_s[SABER_NOISE_SEEDBYTES];
	int i, j;

	//randombytes(seed_A, SABER_SEEDBYTES); //change
	f_rng(p_rng, seed_A, SABER_SEEDBYTES);
	shake128(seed_A, SABER_SEEDBYTES, seed_A, SABER_SEEDBYTES); // for not revealing system RNG state
	f_rng(p_rng, seed_s, SABER_NOISE_SEEDBYTES);
	//randombytes(seed_s, SABER_NOISE_SEEDBYTES);

	GenMatrix(A, seed_A);
	GenSecret(s, seed_s);
	MatrixVectorMul(A, s, b, 1);

	for (i = 0; i < SABER_L; i++)
	{
		for (j = 0; j < SABER_N; j++)
		{
			b[i][j] = (b[i][j] + h1) >> (SABER_EQ - SABER_EP);
		}
	}

	POLVECq2BS(sk, s);
	POLVECp2BS(pk, b);
	memcpy(pk + SABER_POLYVECCOMPRESSEDBYTES, seed_A, sizeof(seed_A));
}

/*void GenMatrix(polyvec *a, const unsigned char *seed)
{
  unsigned int one_vector=13*SABER_N/8;
  unsigned int byte_bank_length=SABER_K*SABER_K*one_vector;
  unsigned char buf[byte_bank_length];

  uint16_t temp_ar[SABER_N];

  int i,j,k;
  uint16_t mod = (SABER_Q-1);

  shake128(buf,byte_bank_length,seed,SABER_SEEDBYTES);
  
  for(i=0;i<SABER_K;i++)
  {
    for(j=0;j<SABER_K;j++)
    {
	BS2POLq(buf+(i*SABER_K+j)*one_vector,temp_ar);
	for(k=0;k<SABER_N;k++){
		a[i].vec[j].coeffs[k] = (temp_ar[k])& mod ;
	}
    }
  }
  mbedtls_free(buf);
}


void indcpa_kem_keypair(unsigned char *pk, 
						unsigned char *sk,
						int(*f_rng)(void *, unsigned char *, size_t), 
						void *p_rng)

{
  polyvec a[SABER_K];// skpv;

  //polyvec skpv;
  uint16_t skpv[SABER_K][SABER_N];
 
  unsigned char seed[SABER_SEEDBYTES];
  unsigned char noiseseed[SABER_COINBYTES];
  int32_t i,j;


  uint16_t res[SABER_K][SABER_N];
  //uint16_t acc[SABER_N];  
  //uint16_t mod=SABER_Q-1;

  f_rng(p_rng, seed, SABER_SEEDBYTES);
  shake128(seed, SABER_SEEDBYTES, seed, SABER_SEEDBYTES); // for not revealing system RNG state
  rf_rng(p_rng,noiseseed, SABER_COINBYTES);

  GenMatrix(a, seed);	//sample matrix A

  GenSecret(skpv,noiseseed);//generate secret from constant-time binomial distribution


 /* for(i=0;i<SABER_K;i++){
	for(j=0;j<SABER_N;j++){
		printf("%u\t",skpv[i][j]);
	}
	printf("\n-----------\n");
  }
*/
  //------------------------do the matrix vector multiplication and rounding------------
/*
	for(i=0;i<SABER_K;i++){
		for(j=0;j<SABER_N;j++){
			res[i][j]=0;
		}
	}

	MatrixVectorMul(a,skpv,res,SABER_Q-1,0);
		

	  //-----now rounding

	for(i=0;i<SABER_K;i++){ //shift right 3 bits
		for(j=0;j<SABER_N;j++){
			res[i][j]=res[i][j] + 4;
			res[i][j]=(res[i][j]>>3);
		}
	}




	//------------------unload and pack sk=3 x (256 coefficients of 14 bits)-------
		
	POLVECq2BS(sk,skpv); // load the sectret-key coefficients

	//------------------unload and pack pk=256 bits seed and 3 x (256 coefficients of 11 bits)-------

	
	POLVECp2BS(pk,res); // load the public-key coefficients



	for(i=0;i<SABER_SEEDBYTES;i++){ // now load the seedbytes in PK. Easy since seed bytes are kept in byte format.
		pk[SABER_POLYVECCOMPRESSEDBYTES + i]=seed[i]; 
	}

}*/

void indcpa_kem_enc(const uint8_t m[SABER_KEYBYTES], const uint8_t seed_sp[SABER_NOISE_SEEDBYTES], const uint8_t pk[SABER_INDCPA_PUBLICKEYBYTES], uint8_t ciphertext[SABER_BYTES_CCA_DEC])
{
	uint16_t A[SABER_L][SABER_L][SABER_N];
	uint16_t sp[SABER_L][SABER_N];
	uint16_t bp[SABER_L][SABER_N] = {0};
	uint16_t vp[SABER_N] = {0};
	uint16_t mp[SABER_N];
	uint16_t b[SABER_L][SABER_N];
	int i, j;
	const uint8_t *seed_A = pk + SABER_POLYVECCOMPRESSEDBYTES;

	GenMatrix(A, seed_A);
	GenSecret(sp, seed_sp);
	MatrixVectorMul(A, sp, bp, 0);

	for (i = 0; i < SABER_L; i++)
	{
		for (j = 0; j < SABER_N; j++)
		{
			bp[i][j] = (bp[i][j] + h1) >> (SABER_EQ - SABER_EP);
		}
	}

	POLVECp2BS(ciphertext, bp);
	BS2POLVECp(pk, b);
	InnerProd(b, sp, vp);

	BS2POLmsg(m, mp);

	for (j = 0; j < SABER_N; j++)
	{
		vp[j] = (vp[j] - (mp[j] << (SABER_EP - 1)) + h1) >> (SABER_EP - SABER_ET);
	}

	POLT2BS(ciphertext + SABER_POLYVECCOMPRESSEDBYTES, vp);
}

/*void indcpa_kem_enc(const unsigned char *message_received, 
	const unsigned char *noiseseed, 
	const unsigned char *pk, 
	unsigned char *ciphertext)
{ 

	uint32_t i,j,k;
	polyvec a[SABER_K];		// skpv;
	unsigned char seed[SABER_SEEDBYTES];
	uint16_t pkcl[SABER_K][SABER_N]; 	//public key of received by the client



	uint16_t skpv1[SABER_K][SABER_N];

	uint16_t message[SABER_KEYBYTES*8];

	uint16_t res[SABER_K][SABER_N];
	//uint16_t acc[SABER_N];  
	//uint16_t mod=SABER_Q-1;
	uint16_t mod_p=SABER_P-1;
	
	uint16_t vprime[SABER_N];

	//uint16_t ciphertext_temp[SABER_N];


	unsigned char rec_c[SABER_RECONBYTES_KEM];
	
	for(i=0;i<SABER_SEEDBYTES;i++){ // extract the seedbytes from Public Key.
		seed[i]=pk[ SABER_POLYVECCOMPRESSEDBYTES + i]; 
	}


	GenMatrix(a, seed);				

	GenSecret(skpv1,noiseseed);//generate secret from constant-time binomial distribution

	//-----------------matrix-vector multiplication and rounding

	for(i=0;i<SABER_K;i++){
		for(j=0;j<SABER_N;j++){
			res[i][j]=0;
		}
	}

	MatrixVectorMul(a,skpv1,res,SABER_Q-1,1);
	
	  //-----now rounding

	for(i=0;i<SABER_K;i++){ //shift right 3 bits
		for(j=0;j<SABER_N;j++){
			res[i][j]=res[i][j]+ 4;
			res[i][j]=(res[i][j]>> 3);
		}
	}


	POLVECp2BS(ciphertext,res);

//*******************************************************************client matrix-vector multiplication ends************************************

	//------now calculate the v'

	//-------unpack the public_key

	BS2POLVECp(pk, pkcl); //pkcl is the b in the protocol



	for(i=0;i<SABER_N;i++)
		vprime[i]=0;

	for(i=0;i<SABER_K;i++){
		for(j=0;j<SABER_N;j++){
			skpv1[i][j]=skpv1[i][j] & (mod_p);
		}
	}

	// vector-vector scalar multiplication with mod p
	VectorMul(pkcl,skpv1,mod_p,vprime);


	// unpack message_received;
	for(j=0; j<SABER_KEYBYTES; j++)
	{
		for(i=0; i<8; i++)
		{
			message[8*j+i] = ((message_received[j]>>i) & 0x01);
		}
	}


	// message encoding
	for(i=0; i<SABER_N; i++)
	{
		message[i] = (message[i]<<9);
	}



	for(k=0;k<SABER_N;k++)
	{
		vprime[k]=vprime[k]+ message[k];
	}

	ReconDataGen(vprime,rec_c);

	for(j=0;j<SABER_RECONBYTES_KEM;j++){
		ciphertext[SABER_POLYVECCOMPRESSEDBYTES + j] = rec_c[j];
	}
	
}*/

void indcpa_kem_dec(const uint8_t sk[SABER_INDCPA_SECRETKEYBYTES], const uint8_t ciphertext[SABER_BYTES_CCA_DEC], uint8_t m[SABER_KEYBYTES])
{

	uint16_t s[SABER_L][SABER_N];
	uint16_t b[SABER_L][SABER_N];
	uint16_t v[SABER_N] = {0};
	uint16_t cm[SABER_N];
	int i;

	BS2POLVECq(sk, s);
	BS2POLVECp(ciphertext, b);
	InnerProd(b, s, v);
	BS2POLT(ciphertext + SABER_POLYVECCOMPRESSEDBYTES, cm);

	for (i = 0; i < SABER_N; i++)
	{
		v[i] = (v[i] + h2 - (cm[i] << (SABER_EP - SABER_ET))) >> (SABER_EP - 1);
	}

	POLmsg2BS(m, v);
}

/*void indcpa_kem_dec(const unsigned char *sk, const unsigned char *ciphertext, unsigned char message_dec[])
{

	uint32_t i,j;
	
	
	uint16_t sksv[SABER_K][SABER_N]; //secret key of the server
	

	uint16_t pksv[SABER_K][SABER_N];
	
	//uint16_t recon_ar[SABER_N];
	unsigned char recon_ar[SABER_RECONBYTES_KEM];
	uint16_t message_dec_unpacked[SABER_KEYBYTES*8];	// one element containes on decrypted bit;

	
	//uint16_t acc[SABER_N];  

	uint16_t mod_p=SABER_P-1;

	uint16_t v[SABER_N];

	BS2POLVECq(sk, sksv); //sksv is the secret-key
	BS2POLVECp(ciphertext, pksv); //pksv is the ciphertext


	// vector-vector scalar multiplication with mod p
	for(i=0;i<SABER_N;i++)
		v[i]=0;

	for(i=0;i<SABER_K;i++){
		for(j=0;j<SABER_N;j++){
			sksv[i][j]=sksv[i][j] & (mod_p);
		}
	}

	VectorMul(pksv,sksv,mod_p,v);

	//Extraction
	for(i=0;i<SABER_RECONBYTES_KEM;i++){
		recon_ar[i]=ciphertext[SABER_POLYVECCOMPRESSEDBYTES+i];
	}

	Recon(v,recon_ar,message_dec_unpacked);
	

	// pack decrypted message
	POL2MSG(message_dec_unpacked, message_dec);
}*/

/*void MatrixVectorMul(polyvec *a, uint16_t skpv[SABER_K][SABER_N], uint16_t res[SABER_K][SABER_N], uint16_t mod, int16_t transpose){

	uint16_t acc[SABER_N]; 
	int32_t i,j,k;

	if(transpose==1){
		for(i=0;i<SABER_K;i++){
			for(j=0;j<SABER_K;j++){
				pol_mul((uint16_t *)&a[j].vec[i], skpv[j], acc, SABER_Q, SABER_N,0);			

				for(k=0;k<SABER_N;k++){
					res[i][k]=res[i][k]+acc[k];
					res[i][k]=(res[i][k]&mod); //reduction mod p
					acc[k]=0; //clear the accumulator
				}
			
			}
		}
	}
	else{

		for(i=0;i<SABER_K;i++){
			for(j=0;j<SABER_K;j++){
				pol_mul((uint16_t *)&a[i].vec[j], skpv[j], acc, SABER_Q, SABER_N,0);			
				for(k=0;k<SABER_N;k++){
					res[i][k]=res[i][k]+acc[k];
					res[i][k]=res[i][k]&mod; //reduction
					acc[k]=0; //clear the accumulator
				}
			
			}
		}
	}
				

}

void POL2MSG(uint16_t *message_dec_unpacked, unsigned char *message_dec){

	int32_t i,j;

	for(j=0; j<SABER_KEYBYTES; j++)
	{
		message_dec[j] = 0;
		for(i=0; i<8; i++)
		message_dec[j] = message_dec[j] | (message_dec_unpacked[j*8 + i] <<i);
	} 

}


void VectorMul(uint16_t pkcl[SABER_K][SABER_N],uint16_t skpv[SABER_K][SABER_N],uint16_t mod,uint16_t res[SABER_N]){


	uint32_t j,k;
	uint16_t acc[SABER_N]; 

	// vector-vector scalar multiplication with mod p
	for(j=0;j<SABER_K;j++){
		pol_mul(pkcl[j], skpv[j], acc , SABER_P, SABER_N,0);

			for(k=0;k<SABER_N;k++){
				res[k]=res[k]+acc[k];
				res[k]=res[k]&mod; //reduction
				acc[k]=0; //clear the accumulator
			}
	}




}*/

