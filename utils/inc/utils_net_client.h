//
// Created by carlos on 2020/12/28.
//

#ifndef CARLOS_OPENMBED_UTILS_NET_CLIENT_H
#define CARLOS_OPENMBED_UTILS_NET_CLIENT_H

#include "mbedtls_common.h"
#include <mbedtls/net.h>

int utils_net_client_free();
int utils_net_client_init(const char *bind_ip, const char *port, int proto);
int utils_net_client_send(const unsigned char *buf, size_t len);
int utils_net_client_recv(unsigned char* buf, size_t max_len);
int utils_net_client_recv_timeout(unsigned char* buf, size_t max_len, uint32_t timeout);

#endif //CARLOS_OPENMBED_UTILS_NET_CLIENT_H
