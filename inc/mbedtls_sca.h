//
// Created by carlos on 2021/2/22.
//

#ifndef CARLOS_OPENMBED_MBEDTLS_AES_H
#define CARLOS_OPENMBED_MBEDTLS_AES_H

#include "mbedtls_common.h"
#include <mbedtls/aes.h>
#include <mbedtls/cipher.h>

int mbedtls_cipher_user_encrypt(const unsigned char* plain_text, size_t plain_len,
                                const unsigned char* iv, size_t iv_len,
                                const unsigned char* key, size_t key_len,
                                unsigned char *out_buffer, size_t *out_len, int mbedtls_aes_type);

int mbedtls_cipher_user_decrypt(const unsigned char* cipher_text, size_t cipher_len,
                                const unsigned char* iv, size_t iv_len,
                                const unsigned char* key, size_t key_len,
                                unsigned char *out_buffer, size_t *out_len, int mbedtls_aes_type);

#endif //CARLOS_OPENMBED_MBEDTLS_AES_H
