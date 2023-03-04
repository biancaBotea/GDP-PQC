#ifndef MY_HEADER_H
# define MY_HEADER_H

#include "mbedtls/ssl.h"

mbedtls_pq_avg_performance run_server(const char *cert, const char *key, const int cipher_suite, char *MsgToClient);

#endif