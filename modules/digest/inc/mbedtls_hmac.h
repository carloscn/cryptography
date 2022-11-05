#ifndef CARLOS_OPENMBED_MBEDTLS_HMAC_H
#define CARLOS_OPENMBED_MBEDTLS_HMAC_H
#include "mbedtls_common.h"
#include "mbedtls/md.h"

int mbedtls_hmac_sha384(const unsigned char *key,
                        size_t key_byte_size,
                        const unsigned char *input,
                        size_t input_byte_size,
                        unsigned char output[48]);

#endif //CARLOS_OPENMBED_MBEDTLS_HMAC_H