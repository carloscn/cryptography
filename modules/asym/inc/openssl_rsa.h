//
// Created by Carlos on 2020/9/5.
//

#ifndef WARM_OPENSSL_OPENSSL_RSA_H
#define WARM_OPENSSL_OPENSSL_RSA_H

#include "openssl_common.h"
#include <openssl/rsa.h>
#include <openssl/bn.h>

int openssl_gen_rsa_pkcs1_pem_files(const char *pub_keyfile, const char *pri_keyfile,
                           const unsigned char *passwd, int passwd_len, RSA_KEY_LEN rsa_key_len);
int openssl_gen_rsa_pkcs8_pem_files(const char *pub_keyfile, const char *pri_keyfile,
                                    const unsigned char *passwd, int passwd_len, RSA_KEY_LEN rsa_key_len);
int openssl_evp_pkcs1_rsa_encrypt(unsigned char *plain_text, size_t plain_len,
                                  unsigned char **cipher_text, size_t *cipher_len,
                                  unsigned char *pem_file);
int openssl_evp_pkcs1_rsa_decrypt(unsigned char *cipher_text, size_t cipher_len,
                                  unsigned char **plain_text, size_t *plain_len,
                                  const unsigned char *pem_file, const unsigned char *passwd);
int openssl_evp_pkcs8_rsa_encrypt(unsigned char *plain_text, size_t plain_len,
                                  unsigned char **cipher_text, size_t *cipher_len,
                                  unsigned char *pem_file);
int openssl_evp_pkcs8_rsa_decrypt(unsigned char *cipher_text, size_t cipher_len,
                                  unsigned char **plain_text, size_t *plain_len,
                                  const unsigned char *pem_file, const unsigned char *passwd);
int openssl_evp_pkcs1_rsa_signature(unsigned char *sign_rom, size_t sign_rom_len,
                                    unsigned char *result, size_t *result_len,
                                    SCHEME_TYPE type,
                                    const unsigned char *priv_pem_file, const unsigned char *passwd);
int openssl_evp_pkcs1_rsa_verify(unsigned char *sign_rom, size_t sign_rom_len,
                                 unsigned char *result, size_t result_len,
                                 SCHEME_TYPE type,
                                 const unsigned char *pub_pem_file);
int openssl_evp_pkcs8_rsa_signature(unsigned char *sign_rom, size_t sign_rom_len,
                                    unsigned char *result, size_t *result_len,
                                    SCHEME_TYPE  type,
                                    const unsigned char *priv_pem_file, const unsigned char *passwd);
int openssl_evp_pkcs8_rsa_verify(unsigned char *sign_rom, size_t sign_rom_len,
                                 unsigned char *result, size_t result_len,
                                 SCHEME_TYPE type,
                                 const unsigned char *pub_pem_file);
#endif //WARM_OPENSSL_OPENSSL_RSA_H
