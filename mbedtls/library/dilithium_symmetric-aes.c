#include <stdint.h>
#include "pq/dilithium_symmetric.h"
#include "pq/aes256ctr.h"

void dilithium_aes256ctr_init(aes256ctr_ctx *state,
                              const unsigned char key[32],
                              uint16_t nonce)
{
  unsigned char expnonce[12] = {0};
  expnonce[0] = nonce;
  expnonce[1] = nonce >> 8;
  aes256ctr_init(state, key, expnonce);
}
