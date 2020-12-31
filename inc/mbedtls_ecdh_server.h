//
// Created by carlos on 2020/12/30.
//

#ifndef CARLOS_OPENMBED_MBEDTLS_ECDH_SERVER_H
#define CARLOS_OPENMBED_MBEDTLS_ECDH_SERVER_H

#include "mbedtls_common.h"
#include <mbedtls/ecdh.h>
#include "utils_net_sever.h"
#include "mbedtls_rsa.h"

#define PRIVATE_RSA_KEY_FILE "rsaprikey.pem"
#define ECDHM_PRIME_FILE "ecdhm.txt"

int mbedtls_ecdh_server_entry();
#endif //CARLOS_OPENMBED_MBEDTLS_ECDH_SERVER_H
