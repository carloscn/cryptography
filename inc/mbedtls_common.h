//
// Created by carlos on 2020/12/23.
//

#ifndef CARLOS_OPENMBED_MBEDTLS_COMMON_H
#define CARLOS_OPENMBED_MBEDTLS_COMMON_H

#include "mbedtls_cfg.h"
#include <mbedtls/config.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/platform.h>
#include <mbedtls/pk.h>


mbedtls_md_type_t get_mbedtls_scheme(SCHEME_TYPE sch);
#endif //CARLOS_OPENMBED_MBEDTLS_COMMON_H
