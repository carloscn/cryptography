//
// Created by 魏昊晨 on 2020/9/5.
//

#ifndef WARM_OPENSSL_TEST_CASE_H
#define WARM_OPENSSL_TEST_CASE_H
#include "openssl_rsa.h"
#include "openssl_sm2.h"
#include "openssl_md_sha.h"
#include "openssl_ecc.h"
#include "mbedtls_md_sha.h"
#include "mbedtls_rsa.h"
#include "mbedtls_ecc.h"

#define PRIVATE_SM2_KEY_FILE "sm2prikey.pem"
#define PUBLIC_SM2_KEY_FILE "sm2pubkey.pem"
#define PRIVATE_RSA_KEY_FILE "rsaprikey.pem"
#define PUBLIC_RSA_KEY_FILE "rsapubkey.pem"
#define PRIVATE_ECC_KEY_FILE "eccprikey.pem"
#define PUBLIC_ECC_KEY_FILE "eccpubkey.pem"

int openssl_md5_test_out(unsigned char *content, uint64_t len, unsigned char *out);
int test_evp_sm2_signature_verify();
int test_evp_pkcs1_rsa_signature_verify();
int test_evp_pkcs8_rsa_signature_verify();
int test_mbedtls_rsa_encrypt_decrypt();
int test_md5();
int test_evp_md5();
int test_mbedtls_md5();
int test_evp_sm2_encrypt_decrypt();
int test_evp_pkcs1_rsa_encrypt_decrypt();
int test_evp_pkcs8_rsa_encrypt_decrypt();
int test_mbedtls_ecc_enc_dec();
int mbedtls_test_rsa_enc_dec();
int mbedtls_test_ecc_sign_verfiy();
int mbedtls_test_rsa_sign_verify();
int test_mbedtls_ecc_encrypt_decrypt();
int test_evp_ecc_signature_verify();
#endif //WARM_OPENSSL_TEST_CASE_H
