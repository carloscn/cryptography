//
// Created by carwei01 on 10/20/2020.
//

#ifndef CARLOS_OPENMBED_OPENSSL_ECC_H
#define CARLOS_OPENMBED_OPENSSL_ECC_H

#include "openssl_common.h"
#include <openssl/ecdh.h>
#include "openssl_md_sha.h"

int openssl_evp_ecc_encrypt(const unsigned char *plain_text, size_t plain_len,
                            unsigned char *cipher_text, size_t *cipher_len,
                            unsigned char *pem_file);
int openssl_evp_ecc_decryt(const unsigned char *cipher_text, size_t cipher_len,
                           unsigned char *plain_text, size_t *plain_len,
                           const unsigned char *pem_file, const unsigned char *passwd);
int openssl_evp_pk_ecc_signature(const unsigned char *sign_rom, size_t sign_rom_len,
                                 unsigned char *result, size_t *result_len,
                                 SCHEME_TYPE sch,
                                 const unsigned char *priv_pem_file, const unsigned char *passwd);
int openssl_evp_pk_ecc_verify(const unsigned char *sign_rom, size_t sign_rom_len,
                              const unsigned char *result, size_t result_len,
                              SCHEME_TYPE sch,
                              const unsigned char *pub_pem_file);
int openssl_evp_ecdsa_signature(const unsigned char *sign_rom, size_t sign_rom_len,
                                unsigned char *result, size_t *result_len,
                                SCHEME_TYPE sch,
                                const unsigned char *priv_pem_file, const unsigned char *passwd);
int openssl_evp_ecdsa_verify(const unsigned char *sign_rom, size_t sign_rom_len,
                                     const unsigned char *result, size_t result_len,
                                     SCHEME_TYPE sch,
                                     const unsigned char *pub_pem_file);
#endif //CARLOS_OPENMBED_OPENSSL_ECC_H
