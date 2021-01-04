//
// Created by carlos on 2020/12/30.
//

#ifndef CARLOS_OPENMBED_MBEDTLS_ECDH_CLIENT_H
#define CARLOS_OPENMBED_MBEDTLS_ECDH_CLIENT_H

#include "mbedtls_common.h"
#include <mbedtls/ecdh.h>
#include "utils_net_client.h"
#include "mbedtls_rsa.h"

#define PUBLIC_RSA_KEY_FILE "rsapubkey.pem"
#define ECDHM_PRIME_FILE "ecdhm.txt"

int mbedtls_ecdh_client_entry();

#endif //CARLOS_OPENMBED_MBEDTLS_ECDH_CLIENT_H
