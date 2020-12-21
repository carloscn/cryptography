//
// Created by carlos on 2020/11/2.
//

#ifndef CARLOS_OPENMBED_MBEDTLS_RSA_H
#define CARLOS_OPENMBED_MBEDTLS_RSA_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mbedtls/config.h>
#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/platform.h>
#include "mbedtls_md_sha.h"
#include "mbedlts_cfg.h"
#include "errors.h"

int mbedtls_gen_rsa_pem_key_files(const char *pub_keyfile, const char *pri_keyfile,
                                  const unsigned char *passwd, int passwd_len, unsigned int key_size);
int mbedtls_gen_rsa_raw_key_files(const char *pub_keyfile, const char *pri_keyfile,
                                  const unsigned char *passwd, int passwd_len, unsigned int key_size);
int mbedtls_rsa_pkcs8_encrypt(unsigned char *plain_text, size_t plain_len,
                              unsigned char *cipher_text, size_t *cipher_len,
                              unsigned char *pem_file);
int mbedtls_rsa_pkcs8_decrypt(unsigned char *cipher_text, size_t cipher_len,
                              unsigned char *plain_text, size_t *plain_len,
                              const unsigned char *pem_file, const unsigned char *passwd);
int mbedtls_rsa_pkcs1_encryption(unsigned char *plain_text, size_t plain_len,
                                 unsigned char **cipher_text, size_t *cipher_len,
                                 unsigned char *pem_file);
int mbedtls_rsa_pkcs1_decryption(unsigned char *cipher_text, size_t cipher_len,
                                 unsigned char **plain_text, size_t *plain_len,
                                 const unsigned char *pem_file, const unsigned char *passwd);
int mbedtls_rsa_pkcs8_signature(unsigned char *sign_rom, size_t sign_rom_len,
                                unsigned char *result, size_t *result_len,
                                const unsigned char *priv_pem_file, const unsigned char *passwd);
int mbedtls_rsa_pkcs8_verified(unsigned char *sign_rom, size_t sign_rom_len,
                               unsigned char *result, size_t result_len,
                               const unsigned char *pub_pem_file);
int mbedtls_rsa_pkcs1_signature(unsigned char *sign_rom, size_t sign_rom_len,
                                unsigned char *result, size_t *result_len,
                                const unsigned char *priv_pem_file, const unsigned char *passwd);
int mbedtls_rsa_pkcs1_verified(unsigned char *sign_rom, size_t sign_rom_len,
                               unsigned char *result, size_t result_len,
                               const unsigned char *pub_pem_file);
#endif //CARLOS_OPENMBED_MBEDTLS_RSA_H
