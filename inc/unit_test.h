//
// Created by 魏昊晨 on 2020/9/5.
//

#ifndef WARM_OPENSSL_TEST_CASE_H
#define WARM_OPENSSL_TEST_CASE_H
#include "openssl_rsa.h"
#include "openssl_sm2.h"
#include "openssl_md_sha.h"
#include "mbedtls_md_sha.h"
#include "mbedtls_rsa.h"

#define PRIVATE_SM2_KEY_FILE "sm2prikey.pem"
#define PUBLIC_SM2_KEY_FILE "sm2pubkey.pem"
#define PRIVATE_RSA_KEY_FILE "rsaprikey.pem"
#define PUBLIC_RSA_KEY_FILE "rsapubkey.pem"

int openssl_md5_test_out(unsigned char *content, uint64_t len, unsigned char *out);
int test_evp_sm2_signature_verify();
int test_evp_rsa_signature_verify();
int test_md5();
int test_evp_md5();
int test_mbedtls_md5();
int test_evp_sm2_encrypt_decrypt();
int test_evp_rsa_encrypt_decrypt();

#endif //WARM_OPENSSL_TEST_CASE_H