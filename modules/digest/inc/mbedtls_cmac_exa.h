//
// Created by carwei01 on 2021/6/11.
//

#ifndef CARLOS_OPENMBED_MBEDTLS_CMAC_EXA_H
#define CARLOS_OPENMBED_MBEDTLS_CMAC_EXA_H
#include "mbedtls_common.h"
#include "mbedtls/cmac.h"
#include "mbedtls/cipher.h"

int mbedtls_cmac_aes_128_ecb(const unsigned char *key, size_t key_byte_size,
                             const unsigned char *input, size_t input_byte_size,
                             unsigned char *output, size_t *output_byte_size);
int mbedtls_cmac_aes_192_ecb(const unsigned char *key, size_t key_byte_size,
                             const unsigned char *input, size_t input_byte_size,
                             unsigned char *output, size_t *output_byte_size);

#endif //CARLOS_OPENMBED_MBEDTLS_CMAC_EXA_H
