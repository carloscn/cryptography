//
// Created by carlos on 2020/11/12.
//

#ifndef CARLOS_OPENMBED_MBEDTLS_ECC_H
#define CARLOS_OPENMBED_MBEDTLS_ECC_H

#include "mbedtls_common.h"
#include "mbedtls_md_sha.h"
#include <mbedtls/ecdsa.h>

int mbedtls_gen_ecc_key(const char *pub_keyfile, const char *pri_keyfile,
                        const unsigned char *passwd, int passwd_len);
int mbedtls_ecc_encrypt(const unsigned char *plain_text, size_t plain_len,
                        unsigned char **cipher_text, size_t *cipher_len,
                        unsigned char *pem_file);
int mbedtls_ecc_decryt(const unsigned char *cipher_text, size_t cipher_len,
                       unsigned char **plain_text, size_t *plain_len,
                       const unsigned char *pem_file, const unsigned char *passwd);
int mbedtls_ecdsa_signature(const unsigned char *sign_rom, size_t sign_rom_len,
                            unsigned char *result, size_t *result_len,
                            SCHEME_TYPE sch,
                            const unsigned char *priv_pem_file, const unsigned char *passwd);
int mbedtls_ecdsa_verified(const unsigned char *sign_rom, size_t sign_rom_len,
                           const unsigned char *result, size_t result_len,
                           SCHEME_TYPE sch,
                           const unsigned char *pub_pem_file);

#endif //CARLOS_OPENMBED_MBEDTLS_ECC_H
