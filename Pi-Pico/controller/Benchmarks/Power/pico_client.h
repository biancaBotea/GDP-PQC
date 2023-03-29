#ifndef CLIENT_HEADER_H
# define CLIENT_HEADER_H

#include "lwip/altcp_tcp.h"

int run_client(const ip_addr_t server_ip, const char *cert, char *msg);
#endif
