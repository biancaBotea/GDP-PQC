#include <stdint.h>
#include "pq/dilithium_params.h"
#include "pq/dilithium_reduce.h"

/*************************************************
* Name:        montgomery_reduce_D
*
* Description: For finite field element a with -2^{31}Q_D <= a <= Q_D*2^31,
*              compute r \equiv a*2^{-32} (mod Q_D) such that -Q_D < r < Q_D.
*
* Arguments:   - int64_t: finite field element a
*
* Returns r.
**************************************************/
int32_t montgomery_reduce_D(int64_t a) {
  int32_t t;

  t = (int64_t)(int32_t)a*QINV;
  t = (a - (int64_t)t*Q_D) >> 32;
  return t;
}

/*************************************************
* Name:        reduce32
*
* Description: For finite field element a with a <= 2^{31} - 2^{22} - 1,
*              compute r \equiv a (mod Q_D) such that -6283009 <= r <= 6283007.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
int32_t reduce32(int32_t a) {
  int32_t t;

  t = (a + (1 << 22)) >> 23;
  t = a - t*Q_D;
  return t;
}

/*************************************************
* Name:        caddq
*
* Description: Add Q_D if input coefficient is negative.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
int32_t caddq(int32_t a) {
  a += (a >> 31) & Q_D;
  return a;
}

/*************************************************
* Name:        freeze_D
*
* Description: For finite field element a, compute standard
*              representative r = a mod^+ Q_D.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
int32_t freeze_D(int32_t a) {
  a = reduce32(a);
  a = caddq(a);
  return a;
}
