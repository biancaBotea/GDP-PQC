/*---------------------------------------------------------------------
This file has been adapted from the implementation 
(available at, Public Domain https://github.com/pq-crystals/kyber) 
of "CRYSTALS – Kyber: a CCA-secure module-lattice-based KEM"
by : Joppe Bos, Leo Ducas, Eike Kiltz, Tancrede Lepoint, 
Vadim Lyubashevsky, John M. Schanck, Peter Schwabe & Damien stehle
----------------------------------------------------------------------*/

#include "pq/saber_api.h"
#include<stdint.h>
#include<stdio.h>//added
#include "pq/saber_params.h"
#include <immintrin.h>//added

static uint64_t load_littleendian(const unsigned char *x, int bytes)
{
  int i;
  uint64_t r = x[0];
  for(i=1;i<bytes;i++)
    r |= (uint64_t)x[i] << (8*i);
  return r;
}


void cbd(uint16_t *r, const unsigned char *buf)
{
	uint16_t Qmod_minus1=SABER_Q-1;

#if Saber_type == 3
  uint32_t t,d, a[4], b[4];
  int i,j;

  for(i=0;i<SABER_N/4;i++)
  {
    t = load_littleendian(buf+3*i,3);
    d = 0;
    for(j=0;j<3;j++)
      d += (t >> j) & 0x249249;

    a[0] =  d & 0x7;
    b[0] = (d >>  3) & 0x7;
    a[1] = (d >>  6) & 0x7;
    b[1] = (d >>  9) & 0x7;
    a[2] = (d >> 12) & 0x7;
    b[2] = (d >> 15) & 0x7;
    a[3] = (d >> 18) & 0x7;
    b[3] = (d >> 21);

    r[4*i+0] = (uint16_t)(a[0]  - b[0]) & Qmod_minus1;
    r[4*i+1] = (uint16_t)(a[1]  - b[1]) & Qmod_minus1;
    r[4*i+2] = (uint16_t)(a[2]  - b[2]) & Qmod_minus1;
    r[4*i+3] = (uint16_t)(a[3]  - b[3]) & Qmod_minus1;

  }
#elif Saber_type == 2

  int i,j;
  uint32_t t1[8];//there will be 8 32 bit integer
  uint32_t d1[4][8];//there will be 8 32 bit integer

  __m256i const_avx, d_avx, t_avx, temp_avx, mask_const_avx, a_avx[4], b_avx[4];

//----------------setting the constants----------------
  __m256i mask;
  unsigned long long int mask_ar[4];
  mask_ar[0]=~(0UL);mask_ar[1]=~(0UL);mask_ar[2]=~(0UL);mask_ar[3]=~(0UL);
  mask = _mm256_loadu_si256 ((__m256i const *)mask_ar);


  const_avx= _mm256_set1_epi32 (0x11111111);
  mask_const_avx= _mm256_set1_epi32 (0xf);

//----------------setting the constants ends----------------

  for(i=0;i<SABER_N/(4*8);i++)
  {
   
	for(j=0;j<8;j++){	
	    t1[j] = load_littleendian(buf+32*i+4*j,4);
	}

	d_avx=_mm256_xor_si256 (d_avx, d_avx);//make d=0

    t_avx=_mm256_loadu_si256 ((__m256i const *) (&t1));//load t	

	for(j=0;j<4;j++){
		temp_avx= _mm256_srli_epi32 (t_avx, j);
		temp_avx=_mm256_and_si256 (temp_avx, const_avx);
		d_avx=_mm256_add_epi32 (d_avx, temp_avx);
		
	} 


	a_avx[0]= _mm256_and_si256(d_avx, mask_const_avx);
	temp_avx= _mm256_srli_epi32(d_avx,4);
	b_avx[0]=_mm256_and_si256 (temp_avx, mask_const_avx);

	temp_avx= _mm256_srli_epi32(d_avx,8);
	a_avx[1]=_mm256_and_si256 (temp_avx, mask_const_avx);
	temp_avx= _mm256_srli_epi32(d_avx,12);
	b_avx[1]=_mm256_and_si256 (temp_avx, mask_const_avx);

	temp_avx= _mm256_srli_epi32(d_avx,16);
	a_avx[2]=_mm256_and_si256 (temp_avx, mask_const_avx);
	temp_avx= _mm256_srli_epi32(d_avx,20);
	b_avx[2]=_mm256_and_si256 (temp_avx, mask_const_avx);

	temp_avx= _mm256_srli_epi32(d_avx,24);
	a_avx[3]=_mm256_and_si256 (temp_avx, mask_const_avx);
	b_avx[3]= _mm256_srli_epi32(d_avx,28);
	
	//--------------------------------
	
	a_avx[0]=_mm256_sub_epi32 (a_avx[0], b_avx[0]);
	a_avx[1]=_mm256_sub_epi32 (a_avx[1], b_avx[1]);
	a_avx[2]=_mm256_sub_epi32 (a_avx[2], b_avx[2]);
	a_avx[3]=_mm256_sub_epi32 (a_avx[3], b_avx[3]);

	//--------------place the values-------
	_mm256_maskstore_epi32 ((int *)d1[0], mask, a_avx[0]);
	_mm256_maskstore_epi32 ((int *)d1[1], mask, a_avx[1]);
	_mm256_maskstore_epi32 ((int *)d1[2], mask, a_avx[2]);
	_mm256_maskstore_epi32 ((int *)d1[3], mask, a_avx[3]);
	
	for(j=0;j<8;j++){	
		r[4*(8*i+j)+0]=d1[0][j] &  Qmod_minus1;
		r[4*(8*i+j)+1]=d1[1][j] &  Qmod_minus1;
		r[4*(8*i+j)+2]=d1[2][j] &  Qmod_minus1;
		r[4*(8*i+j)+3]=d1[3][j] &  Qmod_minus1;
	}
  }

#elif Saber_type == 1
  uint64_t t,d, a[4], b[4];
  int i,j;

  for(i=0;i<SABER_N/4;i++)
  {
    t = load_littleendian(buf+5*i,5);
    d = 0;
    for(j=0;j<5;j++)
      d += (t >> j) & 0x0842108421UL;

    a[0] =  d & 0x1f;
    b[0] = (d >>  5) & 0x1f;
    a[1] = (d >> 10) & 0x1f;
    b[1] = (d >> 15) & 0x1f;
    a[2] = (d >> 20) & 0x1f;
    b[2] = (d >> 25) & 0x1f;
    a[3] = (d >> 30) & 0x1f;
    b[3] = (d >> 35);

    r[4*i+0] = (uint16_t)(a[0]  - b[0]) & Qmod_minus1;
    r[4*i+1] = (uint16_t)(a[1]  - b[1]) & Qmod_minus1;
    r[4*i+2] = (uint16_t)(a[2]  - b[2]) & Qmod_minus1;
    r[4*i+3] = (uint16_t)(a[3]  - b[3]) & Qmod_minus1;
  }
#else
#error "Unsupported SABER parameter."
#endif
}
