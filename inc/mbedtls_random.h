//
// Created by carlos on 2020/12/24.
//

#ifndef CARLOS_OPENMBED_MBEDTLS_RANDOM_H
#define CARLOS_OPENMBED_MBEDTLS_RANDOM_H

#include "mbedtls_common.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/hmac_drbg.h"

int mbedtls_random_request(uint8_t* buf, size_t len);
#endif //CARLOS_OPENMBED_MBEDTLS_RANDOM_H
