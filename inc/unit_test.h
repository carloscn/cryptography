//
// Created by 魏昊晨 on 2020/9/5.
//

#ifndef WARM_OPENSSL_TEST_CASE_H
#define WARM_OPENSSL_TEST_CASE_H
#include <stdlib.h>
#include <stdio.h>
#ifdef _WIN32 or _WIN64
#include <windows.h>
#endif
#ifdef __unix
#include <unistd.h>
#endif
#include "mbedtls_random.h"
#include "openssl_rsa.h"
#include "openssl_sm2.h"
#include "openssl_md_sha.h"
#include "openssl_ecc.h"
#include "mbedtls_md_sha.h"
#include "mbedtls_rsa.h"
#include "mbedtls_ecc.h"
#include "utils_net_client.h"
#include "utils_net_sever.h"
#include "mbedtls_gen_dh.h"
#include "mbedtls_dh_server.h"
#include "mbedtls_dh_client.h"
#include "mbedtls_ecdh_client.h"
#include "mbedtls_ecdh_server.h"
#include "openssl_gen_dh.h"
#include "openssl_dh_server.h"
#include "openssl_dh_client.h"
#include "mbedtls_cert_csr.h"
#include "mbedtls_cert_crt.h"
#include "mbedtls_sca.h"

#define PRIVATE_SM2_KEY_FILE "sm2prikey.pem"
#define PUBLIC_SM2_KEY_FILE "sm2pubkey.pem"
#define PRIVATE_RSA_KEY_FILE "rsaprikey.pem"
#define PUBLIC_RSA_KEY_FILE "rsapubkey.pem"
#define PRIVATE_ECC_KEY_FILE "eccprikey.pem"
#define PUBLIC_ECC_KEY_FILE "eccpubkey.pem"
#define DHM_PRIME_FILE "dhm.txt"
#define ECDHM_PRIME_FILE "ecdhm.txt"

int openssl_md5_test_out(unsigned char *content, uint64_t len, unsigned char *out);
int test_mbedtls_random();
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
int mbedtls_test_ecdsa_sign_verfiy();
int test_evp_ecdsa_signature_verify();
int test_tcp_server();
int test_tcp_client();
int test_gen_dhm();
int test_rsa_dh_client();
int test_rsa_dh_server();
int test_gen_ecdhm();
int test_ecdh_client();
int test_ecdh_server();
int test_cert_req();
int test_cert_crt();
int test_sca();
#endif //WARM_OPENSSL_TEST_CASE_H
