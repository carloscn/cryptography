//
// Created by carlos on 2020/11/2.
//

#ifndef CARLOS_OPENMBED_MBEDTLS_RSA_H
#define CARLOS_OPENMBED_MBEDTLS_RSA_H

#include "mbedtls_common.h"
#include <mbedtls/rsa.h>
#include "mbedtls_md_sha.h"

int mbedtls_get_pem_sig_len(const char* keyfile, bool ispriv, void* passwd);
int mbedtls_gen_rsa_pem_key_files(const char *pub_keyfile, const char *pri_keyfile,
                                  const unsigned char *passwd, int passwd_len, unsigned int key_size);
int mbedtls_gen_rsa_raw_key_files(const char *pub_keyfile, const char *pri_keyfile,
                                  const unsigned char *passwd, int passwd_len, unsigned int key_size);
int mbedtls_rsa_pkcs8_encrypt(const unsigned char *plain_text, size_t plain_len,
                              unsigned char *cipher_text, size_t *cipher_len,
                              unsigned char *pem_file);
int mbedtls_rsa_pkcs8_decrypt(const unsigned char *cipher_text, size_t cipher_len,
                              unsigned char *plain_text, size_t *plain_len,
                              const unsigned char *pem_file, const unsigned char *passwd);
int mbedtls_rsa_pkcs1_encryption(const unsigned char *plain_text, size_t plain_len,
                                 unsigned char **cipher_text, size_t *cipher_len,
                                 unsigned char *pem_file);
int mbedtls_rsa_pkcs1_decryption(const unsigned char *cipher_text, size_t cipher_len,
                                 unsigned char **plain_text, size_t *plain_len,
                                 const unsigned char *pem_file, const unsigned char *passwd);
int mbedtls_rsa_pkcs8_signature(const unsigned char *sign_rom, size_t sign_rom_len,
                                unsigned char *result, size_t *result_len,
                                SCHEME_TYPE sch,
                                const unsigned char *priv_pem_file, const unsigned char *passwd);
int mbedtls_rsa_pkcs8_verified(const unsigned char *sign_rom, size_t sign_rom_len,
                               const unsigned char *result, size_t result_len,
                               SCHEME_TYPE sch,
                               const unsigned char *pub_pem_file);
int mbedtls_rsa_pkcs1_signature(const unsigned char *sign_rom, size_t sign_rom_len,
                                unsigned char *result, size_t *result_len,
                                SCHEME_TYPE sch,
                                const unsigned char *priv_pem_file, const unsigned char *passwd);
int mbedtls_rsa_pkcs1_verified(const unsigned char *sign_rom, size_t sign_rom_len,
                               const unsigned char *result, size_t result_len,
                               SCHEME_TYPE sch,
                               const unsigned char *pub_pem_file);
#endif //CARLOS_OPENMBED_MBEDTLS_RSA_H
