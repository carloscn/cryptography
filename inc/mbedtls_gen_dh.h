//
// Created by carlos on 2020/12/29.
//

#ifndef CARLOS_OPENMBED_MBEDTLS_GEN_DH_H
#define CARLOS_OPENMBED_MBEDTLS_GEN_DH_H

#include "mbedtls_common.h"
#include <mbedtls/dhm.h>
#include <mbedtls/ecdh.h>

int mbedtls_gen_dh_prime(const char *outfile, int nbits);
int mbedtls_gen_ecdh_prime(const char *outfile, int mbedtls_ecp_group_id_x);

#endif //CARLOS_OPENMBED_MBEDTLS_GEN_DH_H
