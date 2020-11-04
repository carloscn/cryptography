//
// Created by 魏昊晨 on 2020/9/5.
//

#ifndef WARM_OPENSSL_OPENSSL_RSA_H
#define WARM_OPENSSL_OPENSSL_RSA_H

#include <openssl/ssl.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include "openssl_cfg.h"

int openssl_gen_rsa_pkcs1_pem_files(const char *pub_keyfile, const char *pri_keyfile,
                           const unsigned char *passwd, int passwd_len, unsigned int key_size);

int openssl_gen_rsa_pkcs8_pem_files(const char *pub_keyfile, const char *pri_keyfile,
                                    const unsigned char *passwd, int passwd_len, unsigned int key_size);
/*openssl rsa decrypt evp using*/
int openssl_evp_rsa_decrypt(unsigned char *cipher_text, size_t cipher_len,
                            unsigned char *plain_text, size_t *plain_len,
                            const unsigned char *pem_file, const unsigned char *passwd);
/*openssl rsa cipher evp using*/
int openssl_evp_rsa_encrypt(	unsigned char *plain_text, size_t plain_len,
                                unsigned char *cipher_text, size_t *cipher_len,
                                unsigned char *pem_file);
// RSA_PKCS1_PADDING  RSA_OAEP_PADDING
int openssl_evp_rsa_signature(unsigned char *sign_rom, size_t sign_rom_len,
                              unsigned char *result, size_t *result_len,
                              const unsigned char *priv_pem_file, const unsigned char *passwd);
/*openssl rsa cipher evp using*/
int openssl_evp_rsa_encrypt(	unsigned char *plain_text, size_t plain_len,
                                unsigned char *cipher_text, size_t *cipher_len,
                                unsigned char *pem_file);
// RSA_PKCS1_PADDING  RSA_OAEP_PADDING
int openssl_evp_rsa_signature(unsigned char *sign_rom, size_t sign_rom_len,
                              unsigned char *result, size_t *result_len,
                              const unsigned char *priv_pem_file, const unsigned char *passwd);
int openssl_evp_rsa_verify(unsigned char *sign_rom, size_t sign_rom_len,
                           unsigned char *result, size_t result_len,
                           const unsigned char *pub_pem_file);
#endif //WARM_OPENSSL_OPENSSL_RSA_H
