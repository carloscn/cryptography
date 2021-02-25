//
// Created by carlos on 2021/2/23.
//

#ifndef CARLOS_OPENMBED_OPENSSL_SCA_H
#define CARLOS_OPENMBED_OPENSSL_SCA_H

#include "openssl_common.h"
#include "openssl/aes.h"
#include "openssl/evp.h"

int openssl_cipher_user_decrypt(const unsigned char* cipher_text, size_t cipher_len,
                                const unsigned char* iv, size_t iv_len,
                                const unsigned char* key, size_t key_len,
                                unsigned char *out_buffer, size_t *out_len, int aes_type);
int openssl_cipher_user_encrypt(const unsigned char* plain_text, size_t plain_len,
                                const unsigned char* iv, size_t iv_len,
                                const unsigned char* key, size_t key_len,
                                unsigned char *out_buffer, size_t *out_len, int aes_type);

#endif //CARLOS_OPENMBED_OPENSSL_SCA_H
