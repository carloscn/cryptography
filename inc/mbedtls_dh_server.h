//
// Created by carlos on 2020/12/29.
//

#ifndef CARLOS_OPENMBED_MBEDTLS_DH_SERVER_H
#define CARLOS_OPENMBED_MBEDTLS_DH_SERVER_H

#include "mbedtls_common.h"
#include <mbedtls/dhm.h>
#include "utils_net_sever.h"
#include "mbedtls_rsa.h"

#define PRIVATE_RSA_KEY_FILE "rsaprikey.pem"
#define DHM_PRIME_FILE "dhm.txt"

int mbedtls_dh_server_entry();

#endif //CARLOS_OPENMBED_MBEDTLS_DH_SERVER_H
