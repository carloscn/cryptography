//
// Created by carlos on 2020/12/29.
//

#ifndef CARLOS_OPENMBED_MBEDTLS_DH_CLIENT_H
#define CARLOS_OPENMBED_MBEDTLS_DH_CLIENT_H

#include "mbedtls_common.h"
#include <mbedtls/dhm.h>
#include "utils_net_client.h"
#include "mbedtls_rsa.h"

#define PUBLIC_RSA_KEY_FILE "rsapubkey.pem"
#define DHM_PRIME_FILE "dhm.txt"

int mbedtls_dh_client_entry();

#endif //CARLOS_OPENMBED_MBEDTLS_DH_CLIENT_H
