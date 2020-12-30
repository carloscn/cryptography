//
// Created by carlos on 2020/12/23.
//

#ifndef CARLOS_OPENMBED_CFG_H
#define CARLOS_OPENMBED_CFG_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "errors.h"
#include "utils.h"

typedef enum _rsa_key_type_t {
    RSA_LEN_1024 = 0,
    RSA_LEN_2048,
    RSA_LEN_4096,
    RSA_LEN_8192
} RSA_KEY_LEN;

typedef enum _scheme_type_t {
    M_MD5,
    M_SHA1,
    M_SHA224,
    M_SHA256,
    M_SHA384,
    M_SHA512,
    M_SM3
} SCHEME_TYPE;

#endif //CARLOS_OPENMBED_CFG_H
