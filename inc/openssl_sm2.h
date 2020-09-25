//
// Created by 魏昊晨 on 2020/9/5.
//

#ifndef WARM_OPENSSL_OPENSSL_SM2_H
#define WARM_OPENSSL_OPENSSL_SM2_H

#include <openssl/ssl.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/x509.h>


int generate_sm2_key_files(const char *pub_keyfile, const char *pri_keyfile,
                           const unsigned char *passwd, int passwd_len);
/*openssl sm2 cipher evp using*/
int openssl_evp_sm2_encrypt(	unsigned char *plain_text, size_t plain_len,
                                unsigned char *cipher_text, size_t *cipher_len,
                                unsigned char *pem_file);
/*openssl sm2 decrypt evp using*/
int openssl_evp_sm2_decrypt(unsigned char *cipher_text, size_t cipher_len,
                            unsigned char *plain_text, size_t *plain_len,
                            const unsigned char *pem_file, const unsigned char *passwd);
int openssl_evp_sm2_signature(unsigned char *sign_rom, size_t sign_rom_len,
                              unsigned char *result, size_t *result_len,
                              const unsigned char *priv_pem_file, const unsigned char *passwd);
int openssl_evp_sm2_verify(unsigned char *sign_rom, size_t sign_rom_len,
                           unsigned char *result, size_t result_len,
                           const unsigned char *pub_pem_file);
#endif //WARM_OPENSSL_OPENSSL_SM2_H
