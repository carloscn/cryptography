//
// Created by carlos on 2020/12/28.
//

#ifndef CARLOS_OPENMBED_UTILS_NET_SEVER_H
#define CARLOS_OPENMBED_UTILS_NET_SEVER_H

#include "mbedtls_common.h"
#include <mbedtls/net.h>

int utils_net_server_free();
int utils_net_server_init(const char *bind_ip, const char *port, int proto);
int utils_net_server_accept(void *client_ip, size_t buf_size, size_t *ip_len);
int utils_net_server_send(const unsigned char *buf, size_t len);
int utils_net_server_recv(unsigned char* buf, size_t max_len);
int utils_net_server_recv_timeout(unsigned char* buf, size_t max_len, uint32_t timeout);
#endif //CARLOS_OPENMBED_UTILS_NET_SEVER_H
