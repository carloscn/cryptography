//
// Created by carwei01 on 10/20/2020.
//

#ifndef CARLOS_OPENMBED_OPENSSL_ECC_H
#define CARLOS_OPENMBED_OPENSSL_ECC_H

#include <openssl/ssl.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/ecdh.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/x509.h>

int openssl_evp_ecc_encrypt(unsigned char *plain_text, size_t plain_len,
                            unsigned char *cipher_text, size_t *cipher_len,
                            unsigned char *pem_file);
int openssl_evp_ecc_decryt(unsigned char *cipher_text, size_t cipher_len,
                           unsigned char *plain_text, size_t *plain_len,
                           const unsigned char *pem_file, const unsigned char *passwd);
int openssl_evp_ecdsa_signature(unsigned char *sign_rom, size_t sign_rom_len,
                                unsigned char *result, size_t *result_len,
                                const unsigned char *priv_pem_file, const unsigned char *passwd);
int openssl_evp_ecdsa_verify(unsigned char *sign_rom, size_t sign_rom_len,
                             unsigned char *result, size_t result_len,
                             const unsigned char *pub_pem_file);
#endif //CARLOS_OPENMBED_OPENSSL_ECC_H
