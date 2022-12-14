#ifndef CLIENT_HEADER_H
# define CLIENT_HEADER_H

#include "mbedtls/ssl.h"

mbedtls_pq_performance run_client(const char *server_ip, const char *cert, const int cipher_suite, char *MsgToServer);

#endif