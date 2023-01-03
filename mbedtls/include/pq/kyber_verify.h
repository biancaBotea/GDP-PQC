#ifndef KYBER_VERIFY_H
#define KYBER_VERIFY_H

#include <stdio.h>

int verify(const unsigned char *a, const unsigned char *b, size_t len);

void cmov(unsigned char *r, const unsigned char *x, size_t len, unsigned char b);

#endif
