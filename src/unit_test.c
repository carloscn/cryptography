//
// Created by 魏昊晨 on 2020/9/5.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "unit_test.h"

#if 0
int test_evp_pkcs1_rsa_encrypt_decrypt()
{
#define TEST_BUFFER_SIZE 255
    int ret = 0, i = 0;
    unsigned char *cipher_out = NULL;
    unsigned char plain_in[TEST_BUFFER_SIZE];
    unsigned char *decrypt_out = NULL;
    size_t error_count = 0;
    size_t out_len = TEST_BUFFER_SIZE;
    size_t in_len = sizeof(plain_in) / sizeof(plain_in[0]);
    srand(time(NULL));
    for (i = 0; i < in_len; i ++) {
        plain_in[i] = rand();
    }
    printf("in len: %ld\n", in_len);
    ret = openssl_gen_rsa_pkcs1_pem_files(PUBLIC_RSA_KEY_FILE, PRIVATE_RSA_KEY_FILE,
                                          NULL, 0, RSA_LEN_1024);
    if (ret != 0) {
        printf("gen pkcs1 key failed\n");
        goto finish;
    }
    ret = openssl_evp_pkcs1_rsa_encrypt(plain_in, in_len, &cipher_out, &out_len, PUBLIC_RSA_KEY_FILE);
    if (ret != 0) {
        printf("error in encrypt %d\n", ret);
        goto finish;
    }
    printf("rsa plain text is : \n");
    for (i = 0; i < in_len; i ++) {
        if (i % 32 == 0)
            printf("\n");
        printf("0x%2X,", plain_in[i]);
    }
    printf("\n");
    printf("rsa cipher len = %ld text is :\n", out_len);
    for (i = 0; i < out_len; i ++) {
        if (i % 64 == 0)
            printf("\n");
        printf("%02X", cipher_out[i]);
    }
    printf("\n");
    ret = openssl_evp_pkcs1_rsa_decrypt(cipher_out, out_len, &decrypt_out, &in_len, PRIVATE_RSA_KEY_FILE, "12345");
    if (ret != 0) {
        printf("error in decrypt %d\n", ret);
        goto finish;
    }
    printf("rsa decrypt len = %ld  and text is: \n", in_len);
    for (i = 0; i < in_len; i ++) {
        if (i % 32 == 0)
            printf("\n");
        printf("0x%2X,", decrypt_out[i]);
    }
    printf("\n");
    for (i = 0; i < in_len; i ++) {
        if (plain_in[i] != decrypt_out[i]) {
            printf("error pos: %d, error code 0x%2X ~ 0x%2X\n", i, decrypt_out[i], plain_in[i]);
            error_count ++;
        }
    }
    printf("error count %ld\n", error_count);
    finish:
    if (cipher_out != NULL)
        free(cipher_out);
    if (decrypt_out != NULL)
        free(decrypt_out);
    return ret;
}

int test_evp_pkcs8_rsa_encrypt_decrypt()
{
    int ret = 0, i = 0;
    unsigned char *cipher_out = NULL;
    unsigned char plain_in[TEST_BUFFER_SIZE];
    unsigned char *decrypt_out = NULL;
    size_t error_count = 0;
    size_t out_len = TEST_BUFFER_SIZE;
    size_t in_len = sizeof(plain_in) / sizeof(plain_in[0]);
    for (i = 0; i < in_len; i ++) {
        plain_in[i] = rand();
    }
    printf("in len: %ld\n", in_len);
    ret = openssl_gen_rsa_pkcs8_pem_files(PUBLIC_RSA_KEY_FILE, PRIVATE_RSA_KEY_FILE,
                                          NULL, 0, RSA_LEN_1024);
    if (ret != 0) {
        printf("gen pkcs8 key failed\n");
        goto finish;
    }
    ret = openssl_evp_pkcs8_rsa_encrypt(plain_in, in_len, &cipher_out, &out_len, PUBLIC_RSA_KEY_FILE);
    if (ret != 0) {
        printf("error in encrypt %d\n", ret);
        goto finish;
    }
    printf("rsa plain text is : \n");
    for (i = 0; i < in_len; i ++) {
        if (i % 32 == 0)
            printf("\n");
        printf("0x%2X,", plain_in[i]);
    }
    printf("\n");
    printf("rsa cipher len = %ld text is :\n", out_len);
    for (i = 0; i < out_len; i ++) {
        if (i % 64 == 0)
            printf("\n");
        printf("%02X", cipher_out[i]);
    }
    printf("\n");
    ret = openssl_evp_pkcs8_rsa_decrypt(cipher_out, out_len, &decrypt_out, &in_len, PRIVATE_RSA_KEY_FILE, "12345");
    if (ret != 0) {
        printf("error in decrypt %d\n", ret);
        goto finish;
    }
    printf("rsa decrypt len = %ld  and text is: \n", in_len);
    for (i = 0; i < in_len; i ++) {
        if (i % 32 == 0)
            printf("\n");
        printf("0x%2X,", decrypt_out[i]);
    }
    printf("\n");
    for (i = 0; i < in_len; i ++) {
        if (plain_in[i] != decrypt_out[i]) {
            printf("error pos: %d, error code 0x%2X ~ 0x%2X\n", i, decrypt_out[i], plain_in[i]);
            error_count ++;
        }
    }
    printf("error count %ld\n", error_count);
    finish:
    if (cipher_out != NULL)
        free(cipher_out);
    if (decrypt_out != NULL)
        free(decrypt_out);
    return ret;
}

int test_mbedtls_rsa_encrypt_decrypt()
{
    int ret = 0, i = 0;
    unsigned char *cipher_out = NULL;
    unsigned char plain_in[TEST_BUFFER_SIZE];
    unsigned char *decrypt_out = NULL;
    size_t error_count = 0;
    size_t out_len = TEST_BUFFER_SIZE;
    size_t en_len = (size_t)(sizeof(plain_in) / sizeof(plain_in[0]));
    size_t de_len = 0;
    for (i = 0; i < en_len; i ++) {
        plain_in[i] = rand();
        if (i % 32 == 0)
            printf("\n");
        printf("0x%2X,", plain_in[i]);
    }
    printf("\n");
    ret = openssl_gen_rsa_pkcs1_pem_files(PUBLIC_RSA_KEY_FILE, PRIVATE_RSA_KEY_FILE,
                                          NULL, 0, RSA_LEN_1024);
    if (ret != 0) {
        printf("gen pkcs1 key failed\n");
        goto finish;
    }
    printf("en len: %ld\n", en_len);
    //ret = mbedtls_rsa_pkcs1_encryption(plain_in, en_len, &cipher_out, &out_len, PUBLIC_RSA_KEY_FILE);
    ret = openssl_evp_pkcs1_rsa_encrypt(plain_in, en_len, &cipher_out, &out_len, PUBLIC_RSA_KEY_FILE);
    if (ret != 0) {
        printf("error in encrypt %d\n", ret);
        goto finish;
    }
    printf("rsa cipher len = %ld text is :\n", out_len);
    for (i = 0; i < out_len; i ++) {
        if (i % 64 == 0)
            printf("\n");
        printf("%02X", cipher_out[i]);
    }
    printf("\n");
    ret = mbedtls_rsa_pkcs1_decryption(cipher_out, out_len, &decrypt_out, &de_len, PRIVATE_RSA_KEY_FILE, "12345");
    //ret = openssl_evp_pkcs1_rsa_decrypt(cipher_out, out_len, &decrypt_out, &de_len, PRIVATE_RSA_KEY_FILE, "12345");
    if (ret != 0) {
        printf("error in decrypt %d\n", ret);
        goto finish;
    }
    if (de_len != en_len) {
        printf("error: de_len != en_len\n");
        goto finish;
    }
    printf("rsa decrypt len = %ld  and text is:\n", de_len);
    for (i = 0; i < de_len; i ++) {
        if (i % 32 == 0)
            printf("\n");
        printf("0x%2X,", decrypt_out[i]);
    }
    printf("\n");
    for (i = 0; i < de_len; i ++) {
        if (plain_in[i] != decrypt_out[i]) {
            printf("error pos: %d, error code 0x%2X ~ 0x%2X\n", i, decrypt_out[i], plain_in[i]);
            error_count ++;
        }
    }
    printf("error count %ld\n", error_count);
    finish:
    if (cipher_out != NULL)
        free(cipher_out);
    if (decrypt_out != NULL)
        free(decrypt_out);
    return ret;
}
int test_mbedtls_ecc_encrypt_decrypt()
{
    int ret = 0, i = 0;
    unsigned char *cipher_out = NULL;
    unsigned char plain_in[TEST_BUFFER_SIZE];
    unsigned char *decrypt_out = NULL;
    size_t error_count = 0;
    size_t out_len = TEST_BUFFER_SIZE;
    size_t en_len = (size_t)(sizeof(plain_in) / sizeof(plain_in[0]));
    size_t de_len = 0;
    for (i = 0; i < en_len; i ++) {
        plain_in[i] = rand();
        if (i % 32 == 0)
            printf("\n");
        printf("0x%2X,", plain_in[i]);
    }
    printf("\n");
    ret = mbedtls_gen_ecc_key(PUBLIC_ECC_KEY_FILE, PRIVATE_ECC_KEY_FILE,
                                          NULL, 0);
    if (ret != 0) {
        printf("gen ecc key failed\n");
        goto finish;
    }
    printf("en len: %ld\n", en_len);
    ret = mbedtls_ecc_encrypt(plain_in, en_len, &cipher_out, &out_len, PUBLIC_ECC_KEY_FILE);
    if (ret != 0) {
        printf("error in encrypt %d\n", ret);
        goto finish;
    }
    printf("rsa cipher len = %ld text is :\n", out_len);
    for (i = 0; i < out_len; i ++) {
        if (i % 64 == 0)
            printf("\n");
        printf("%02X", cipher_out[i]);
    }
    printf("\n");
    ret = mbedtls_ecc_decryt(cipher_out, out_len, &decrypt_out, &de_len, PRIVATE_ECC_KEY_FILE, NULL);
    //ret = openssl_evp_pkcs1_rsa_decrypt(cipher_out, out_len, &decrypt_out, &de_len, PRIVATE_RSA_KEY_FILE, "12345");
    if (ret != 0) {
        printf("error in decrypt %d\n", ret);
        goto finish;
    }
    if (de_len != en_len) {
        printf("error: de_len != en_len\n");
        goto finish;
    }
    printf("rsa decrypt len = %ld  and text is:\n", de_len);
    for (i = 0; i < de_len; i ++) {
        if (i % 32 == 0)
            printf("\n");
        printf("0x%2X,", decrypt_out[i]);
    }
    printf("\n");
    for (i = 0; i < de_len; i ++) {
        if (plain_in[i] != decrypt_out[i]) {
            printf("error pos: %d, error code 0x%2X ~ 0x%2X\n", i, decrypt_out[i], plain_in[i]);
            error_count ++;
        }
    }
    printf("error count %ld\n", error_count);
    finish:
    if (cipher_out != NULL)
        free(cipher_out);
    if (decrypt_out != NULL)
        free(decrypt_out);
    return ret;
}
int test_evp_sm2_encrypt_decrypt()
{
    int ret = 0, i = 0;
    unsigned char cipher_out[1024];
    unsigned char plain_in[] = "hi carlos !!!";
    FILE *file = NULL;
    size_t out_len = 1024;
    size_t in_len = strlen(plain_in);

    ret = openssl_evp_sm2_encrypt(plain_in, strlen(plain_in), cipher_out, &out_len, PUBLIC_SM2_KEY_FILE);
    if (ret != 0) {
        printf("error in encrypt %d\n", ret);
        return ret;
    }
    printf("sm2 plain text is : %s \n", plain_in);
    printf("sm2 cipher len = %ld text is :\n", out_len);
    for (i = 0; i < out_len; i ++) {
        printf("%02X", cipher_out[i]);
    }
    file = fopen("enc", "w");
    fwrite(cipher_out, 1, out_len, file);
    fclose(file);
    printf("\n");
    memset(plain_in, '\0', in_len);
    in_len = 1;
    ret = openssl_evp_sm2_decrypt(cipher_out, out_len, plain_in, &in_len, PRIVATE_SM2_KEY_FILE, "12345");
    if (ret != 0) {
        printf("error in decrypt %d\n", ret);
    }
    printf("sm2 decrypt len = %ld  and text is : %s \n", in_len, plain_in);
    return ret;
}

int test_md5()
{
    unsigned char input_str[] = "hello";
    unsigned char outmd[32];
    int ret = 0, i = 0;

    /*open ssl MD5 using*/
    memset(outmd, 0, 32);
    ret = openssl_md5(input_str, strlen(input_str), outmd);
    if (ret != 0) {
        printf("open_ssl_md5 failed: %d\n", ret);
    }
    printf("%s openssl result: ", input_str);
    for(i = 0; i < 16; i++) {
        printf("%02X", outmd[i]);
    }
    printf("\n");
}

int test_evp_md5()
{
    unsigned char input_str[] = "hello";
    unsigned char outmd[32];
    int ret = 0, i = 0;

    /*open ssl evp MD5 using*/
    memset(outmd, 0, 32);
    ret = openssl_evp_md5(input_str, strlen(input_str), outmd);
    if (ret != 0) {
        printf("openssl_evp_md5_test_out failed: %d\n", ret);
    }
    printf("%s evp md5: ", input_str);
    for(i = 0; i < 16; i++) {
        printf("%02X", outmd[i]);
    }
    printf("\n");
    return 0;
}

int test_mbedtls_md5()
{
    unsigned char input_str[] = "hello";
    unsigned char outmd[32];
    int ret = 0, i = 0;

    /*open ssl evp MD5 using*/
    memset(outmd, 0, 32);
    ret = mbedtls_user_md_str(input_str, strlen(input_str), outmd,  "MD5");
    if (ret != 0) {
        printf("mbedtls_md5_test_out failed: %d\n", ret);
    }
    printf("%s mbedtls md5: ", input_str);
    for(i = 0; i < 16; i++) {
        printf("%02X", outmd[i]);
    }
    printf("\n");
    return 0;
}

int test_evp_pkcs1_rsa_signature_verify()
{
    int ret = 0, i = 0;
    unsigned char sign_out[1024];
    unsigned char plain_in[] = "hello carlos.";
    size_t out_len = 256;
    size_t in_len = strlen(plain_in);
    ret = openssl_gen_rsa_pkcs1_pem_files(PUBLIC_RSA_KEY_FILE, PRIVATE_RSA_KEY_FILE,
                                          NULL, 0, RSA_LEN_1024);
    ret = openssl_evp_pkcs1_rsa_signature(plain_in, in_len, sign_out, &out_len, M_SHA256,
                                          PRIVATE_RSA_KEY_FILE, NULL);
    if (ret != 0) {
        printf("rsa signature failed!\n");
        return ret;
    }
    printf("rsa %s openssl sign len = %ld, signature result: \n", plain_in, out_len);
    for(i = 0; i < out_len; i++) {
        printf("%02X", sign_out[i]);
    }
    printf("\n");

    ret = openssl_evp_pkcs1_rsa_verify(sign_out, out_len, plain_in, in_len, M_SHA256,
                                       PUBLIC_RSA_KEY_FILE);
    if (ret != 0) {
        printf("rsa verify failed!\n");
    } else {
        printf("rsa verify succeed!\n");
    }
}

int test_evp_pkcs8_rsa_signature_verify()
{
    int ret = 0, i = 0;
    unsigned char sign_out[1024];
    unsigned char plain_in[] = "hello carlos.";
    size_t out_len = 256;
    size_t in_len = strlen(plain_in);
    ret = openssl_gen_rsa_pkcs8_pem_files(PUBLIC_RSA_KEY_FILE, PRIVATE_RSA_KEY_FILE,
                                          NULL, 0, RSA_LEN_1024);
    ret = openssl_evp_pkcs8_rsa_signature(plain_in, in_len, sign_out, &out_len, M_SHA256,
                                          PRIVATE_RSA_KEY_FILE, NULL);
    if (ret != 0) {
        printf("rsa signature failed!\n");
        return ret;
    }
    printf("rsa %s openssl sign len = %ld, signature result: \n", plain_in, out_len);
    for(i = 0; i < out_len; i++) {
        printf("%02X", sign_out[i]);
    }
    printf("\n");

    ret = openssl_evp_pkcs8_rsa_verify(sign_out, out_len, plain_in, in_len, M_SHA256,
                                       PUBLIC_RSA_KEY_FILE);
    if (ret != 0) {
        printf("rsa verify failed!\n");
    } else {
        printf("rsa verify succeed!\n");
    }
}

int test_evp_sm2_signature_verify()
{
    int ret = 0, i = 0;
    unsigned char sign_out[1024];
    unsigned char plain_in[] = "hello carlos.";
    size_t out_len = 256;
    size_t in_len = strlen(plain_in);

    ret = openssl_evp_sm2_signature(plain_in, in_len, sign_out, &out_len, PRIVATE_SM2_KEY_FILE, "12345");
    if (ret != 0) {
        printf("sm2 signature failed!\n");
        return ret;
    }
    printf("sm2 %s openssl sign len = %ld, signature result: \n", plain_in, out_len);
    for(i = 0; i < out_len; i++) {
        printf("%02X", sign_out[i]);
    }
    printf("\n");
    ret = openssl_evp_sm2_verify(sign_out, out_len, plain_in, in_len, PUBLIC_SM2_KEY_FILE);
    if (ret != 0) {
        ret = -1;
        printf("sm2 verify failed!\n");
    } else {
        ret = 0;
        printf("sm2 verify succeed!\n");
    }
    return ret;
}

int test_mbedtls_ecc_enc_dec()
{
    int ret = 0, i = 0;
    unsigned char cipher_out[1024];
    unsigned char plain_in[4096];
    FILE *file = NULL;
    size_t out_len = 1024;
    size_t in_len = sizeof(plain_in)/sizeof(plain_in[0]);

    for (i = 0; i < 4096; i ++) {
        plain_in[i] = rand();
    }
    ret = mbedtls_rsa_pkcs8_encrypt(plain_in, strlen(plain_in), cipher_out, &out_len, PUBLIC_RSA_KEY_FILE);
    if (ret != 0) {
        printf("error in encrypt %d\n", ret);
        return ret;
    }
    printf("mbedtls rsa plain text is : %s \n", plain_in);
    printf("mbedtls rsa cipher len = %ld text is :\n", out_len);
    printf("     ->>>");
    for (i = 0; i < out_len; i ++) {
        printf("%02X", cipher_out[i]);
    }
    file = fopen("enc", "w");
    fwrite(cipher_out, 1, out_len, file);
    fclose(file);
    printf("\n");
    memset(plain_in, '\0', in_len);
    in_len = 1;
    ret = mbedtls_rsa_pkcs8_decrypt(cipher_out, out_len, plain_in, &in_len, PRIVATE_RSA_KEY_FILE, NULL);
    if (ret != 0) {
        printf("error in decrypt %d\n", ret);
    }
    printf("mbedtls rsa decrypt len = %ld  and text is : %s \n", in_len, plain_in);
    return ret;
}
#if 0
int mbedtls_test_rsa_enc_dec()
{
    int ret = 0, i = 0;
    unsigned char cipher_out[1024];
    unsigned char plain_in[] = "hi carlos !!!";
    FILE *file = NULL;
    size_t out_len = 1024;
    size_t in_len = strlen(plain_in);

    ret = mbedtls_rsa_pkcs1_encryption(plain_in, strlen(plain_in), cipher_out, &out_len, PUBLIC_RSA_KEY_FILE);
    if (ret != 0) {
        printf("error in encrypt %d\n", ret);
        return ret;
    }
    printf("mbedtls rsa plain text is : %s \n", plain_in);
    printf("mbedtls rsa cipher len = %ld text is :\n", out_len);
    printf("     ->>>");
    for (i = 0; i < out_len; i ++) {
        printf("%02X", cipher_out[i]);
    }
    file = fopen("enc", "w");
    fwrite(cipher_out, 1, out_len, file);
    fclose(file);
    printf("\n");
    memset(plain_in, '\0', in_len);
    in_len = 1;
    ret = mbedtls_rsa_pkcs1_decryption(cipher_out, out_len, plain_in, &in_len, PRIVATE_RSA_KEY_FILE, NULL);
    if (ret != 0) {
        printf("error in decrypt %d\n", ret);
    }
    printf("mbedtls rsa decrypt len = %ld  and text is : %s \n", in_len, plain_in);
    return ret;
}
#endif
#if 0
int mbedtls_test_rsa_sign_verfiy()
{
    int ret = 0, i = 0;
    unsigned char sign_out[1024];
    unsigned char plain_in[] = "hello carlos.";
    size_t out_len = 256;
    size_t in_len = strlen(plain_in);

    ret = mbedtls_rsa_pkcs8_signature(plain_in, in_len, sign_out, &out_len, PRIVATE_RSA_KEY_FILE, NULL);
    if (ret != 0) {
        printf("mbedtls ecc signature failed!\n");
        return ret;
    }
    printf("ecc %s mbedtls sign len = %ld, signature result: \n", plain_in, out_len);
    for(i = 0; i < out_len; i++) {
        printf("%02X", sign_out[i]);
    }
    printf("\n");

    ret = mbedtls_rsa_pkcs8_verified(sign_out, out_len, plain_in, in_len, PUBLIC_RSA_KEY_FILE);
    if (ret != 0) {
        printf("mbedtls ecc verify failed!\n");
    } else {
        printf("mbedtls ecc verify succeed!\n");
    }
}
#endif
int mbedtls_test_ecc_sign_verfiy()
{
    int ret = 0, i = 0;
    unsigned char sign_out[1024];
    unsigned char plain_in[] = "hello carlos.";
    size_t out_len = 256;
    size_t in_len = strlen(plain_in);

    ret = mbedtls_pk_ecc_signature(plain_in, in_len, sign_out, &out_len, M_SHA512, PRIVATE_ECC_KEY_FILE, NULL);
    if (ret != 0) {
        printf("mbedtls ecc signature failed!\n");
        return ret;
    }
    printf("ecc %s mbedtls sign len = %ld, signature result: \n", plain_in, out_len);
    for(i = 0; i < out_len; i++) {
        printf("%02X", sign_out[i]);
    }
    printf("\n");

    ret = mbedtls_pk_ecc_verified(sign_out, out_len, plain_in, in_len, M_SHA512, PUBLIC_ECC_KEY_FILE);
    if (ret != 0) {
        printf("mbedtls ecc verify failed!\n");
    } else {
        printf("mbedtls ecc verify succeed!\n");
    }
}
#if 0
int mbedtls_test_rsa_sign_verify()
{
    int ret = 0, i = 0;
    unsigned char sign_out[1024];
    unsigned char plain_in[] = "hello carlos.";
    size_t out_len = 256;
    size_t in_len = strlen(plain_in);

    ret = mbedtls_rsa_pkcs1_signature(plain_in, in_len, sign_out, &out_len, PRIVATE_RSA_KEY_FILE, NULL);
    if (ret != 0) {
        printf("mbedtls rsa signature failed!\n");
        return ret;
    }
    printf("rsa %s mbedtls sign len = %ld, signature result: \n", plain_in, out_len);
    for(i = 0; i < out_len; i++) {
        printf("%02X", sign_out[i]);
    }
    printf("\n");

    ret = mbedtls_rsa_pkcs1_verified(sign_out, out_len, plain_in, in_len, PUBLIC_RSA_KEY_FILE);
    if (ret != 0) {
        printf("mbedtls rsa verify failed!\n");
    } else {
        printf("mbedtls rsa verify succeed!\n");
    }
}
#endif
int test_evp_ecc_signature_verify()
{
    int ret = 0, i = 0;
    unsigned char sign_out[1024];
    unsigned char plain_in[] = "hello carlos.";
    size_t out_len = 256;
    size_t in_len = strlen(plain_in);
    ret = openssl_evp_pk_ecc_signature(plain_in, in_len, sign_out, &out_len, M_SHA256,
                                       PRIVATE_ECC_KEY_FILE, NULL);
    if (ret != 0) {
        printf("oepnssl ecc signature failed!\n");
        return ret;
    }
    printf("openssl ecc %s sign len = %ld, signature result: \n", plain_in, out_len);
    for(i = 0; i < out_len; i++) {
        printf("%02X", sign_out[i]);
    }
    printf("\n");
    ret = mbedtls_pk_ecc_signature(plain_in, in_len, sign_out, &out_len, M_SHA256,
                                   PRIVATE_ECC_KEY_FILE, NULL);
    if (ret != 0) {
        printf("ecc signature failed!\n");
        return ret;
    }
    printf("mbedtls ecc %s sign len = %ld, signature result: \n", plain_in, out_len);
    for(i = 0; i < out_len; i++) {
        printf("%02X", sign_out[i]);
    }
    printf("\n");

    ret = openssl_evp_pk_ecc_verify(sign_out, out_len, plain_in, in_len, M_SHA256,
                                    PUBLIC_ECC_KEY_FILE);
    if (ret != 0) {
        printf("openssl ecc verify failed!\n");
    } else {
        printf("openssl ecc verify succeed!\n");
    }
    ret = mbedtls_pk_ecc_verified(sign_out, out_len, plain_in, in_len, M_SHA256,
                                  PUBLIC_ECC_KEY_FILE);
    if (ret != 0) {
        printf("mbedtls ecc verify failed!\n");
    } else {
        printf("mbedtls ecc verify succeed!\n");
    }
}

int mbedtls_test_ecdsa_sign_verfiy()
{
    int ret = 0, i = 0;
    unsigned char sign_out[1024];
    unsigned char plain_in[] = "hello carlos.";
    size_t out_len = 256;
    size_t in_len = strlen(plain_in);

    ret = mbedtls_ecdsa_signature(plain_in, in_len, sign_out, &out_len, M_SHA512, PRIVATE_ECC_KEY_FILE, NULL);
    if (ret != 0) {
        printf("mbedtls ecdsa signature failed!\n");
        return ret;
    }
    printf("ecdsa %s mbedtls sign len = %ld, signature result: \n", plain_in, out_len);
    for(i = 0; i < out_len; i++) {
        printf("%02X", sign_out[i]);
    }
    printf("\n");

    ret = mbedtls_ecdsa_verified(sign_out, out_len, plain_in, in_len, M_SHA512, PUBLIC_ECC_KEY_FILE);
    if (ret != 0) {
        printf("mbedtls ecdsa verify failed!\n");
    } else {
        printf("mbedtls ecdsa verify succeed!\n");
    }
}

int test_evp_ecdsa_signature_verify()
{
    int ret = 0, i = 0;
    unsigned char sign_out[1024];
    unsigned char plain_in[] = "hello carlos.";
    size_t out_len = 256;
    size_t in_len = strlen(plain_in);
    ret = openssl_evp_ecdsa_signature(plain_in, in_len, sign_out, &out_len, M_SHA256,
                                       PRIVATE_ECC_KEY_FILE, NULL);
    if (ret != 0) {
        printf("oepnssl ecdsa signature failed!\n");
        return ret;
    }
    printf("openssl ecdsa %s sign len = %ld, signature result: \n", plain_in, out_len);
    for(i = 0; i < out_len; i++) {
        printf("%02X", sign_out[i]);
    }
    printf("\n");

    ret = openssl_evp_ecdsa_verify(sign_out, out_len, plain_in, in_len, M_SHA256,
                                    PUBLIC_ECC_KEY_FILE);
    if (ret != 0) {
        printf("openssl ecdsa verify failed!\n");
    } else {
        printf("openssl ecdsa verify succeed!\n");
    }
}

int test_mbedtls_random()
{
    uint8_t buffer[9552];
    int ret = 0;

    ret = mbedtls_random_request(buffer, sizeof(buffer));
    if (ret != 0) {
        printf("mbedtls test random failed\n");
    } else {
        printf("mbedtls test random succuss\n");
        return ret;
    }

    return ret;

}

int test_tcp_server()
{
    int ret = 0;
    const char *server_ip = "192.168.3.79";
    const char *port = "5555";
    char client_ip[255];
    char buffer[4096];
    char *buf = NULL;
    size_t recv_len = 0;
    ret = utils_net_server_init(server_ip, port, MBEDTLS_NET_PROTO_TCP);
    if (ret != ERROR_NONE) {
        printf("init error\n");
        goto finish;
    }
    ret = utils_net_server_accept(client_ip, 4096, (char *)buffer);
    if (ret != ERROR_NONE) {
        printf("server accept failed\n");
        goto finish;
    }
    printf("server accept %s \n", client_ip);
    while(true) {
        utils_net_server_send("nihao", 5);
        sleep(2);
        recv_len = utils_net_server_recv(buffer, 4096);
        if (recv_len > 0) {
            printf("recv : %s\n", buffer);
        }
    }
    finish:
    utils_net_server_free();
    return ret;
}

int test_tcp_client()
{
    int ret = 0;
    const char *server_ip = "192.168.3.79";
    const char *client_ip = "192.168.3.7";
    const char *port = "5555";
    char buffer[4096];
    char *buf = NULL;
    int recv_len = 0;
    ret = utils_net_client_init(client_ip, port, MBEDTLS_NET_PROTO_TCP);
    if (ret != ERROR_NONE) {
        printf("init error\n");
        goto finish;
    }
    while(true) {
        utils_net_client_send("nihao", 5);
        sleep(2);
        recv_len = utils_net_client_recv(buffer, 4096);
        if (recv_len > 0) {
            printf("recv : %s len = %d\n", buffer, recv_len);
        }
    }
    finish:
    utils_net_server_free();
    return ret;
}

int test_gen_dhm()
{
    int ret = 0;
#if 0
    if ((ret = mbedtls_gen_dh_prime(DHM_PRIME_FILE, 2048)) != 0) {
        printf("mbedtls test : gen dh_prime failed returned %d\n", ret);
        return ret;
    }
#endif
    if ((ret = openssl_gen_dh_prime(DHM_PRIME_FILE, 512)) != 0) {
        printf("openssl test : gen dh_prime failed returned %d\n", ret);
        return ret;
    }
}

int test_gen_ecdhm()
{
    int ret = 0;
    if ((ret = mbedtls_gen_ecdh_prime(ECDHM_PRIME_FILE, MBEDTLS_ECP_DP_SECP256R1) != 0)) {
        printf("test : gen ecdh_prime failed returned %d\n", ret);
        return ret;
    }
#if 0
    if ((ret = openssl_gen_ecdh_prime(ECDHM_PRIME_FILE, MBEDTLS_ECP_DP_SECP256R1) != 0)) {
        printf("test : gen ecdh_prime failed returned %d\n", ret);
        return ret;
    }
#endif
}
/*
 * Test for rsa hd server
 * 1. init mbedtls, read (DHP) from dh_prime.txt.
 * 2. init network as server.
 * 3. Accept the client network.
 * 4. Generate the server DH public key(SPUK) randomly.
 *    and mod it to gen server DH private key (SPRK).
 * 5. Using the RSA private key(1024) sign the SPUK.
 * 6. Send SPUK + signed SPUK hash to client. (SHA256)
 * 7. Recv client DH public key(CPUK)
 * 8. Caculate: DHP + SPRK + CPUK = CSK
 * 9. Using the CSK encrypt msg "hello world."
 * 10. Send encrypted msg to Client.
 * */
int test_rsa_dh_server()
{
    int ret = 0;
    ret = mbedtls_dh_server_entry();
    if (ret != 0) {
        printf("test failed for rsa dh server\n");
        return ret;
    }
}

/*
 * Test for rsa hd client.
 * 1. init mbedtls, read (DHP) from dh_prime.txt
 * 2. init network as client.
 * 3. Connect to server network.
 * 4. Recv server's SPUK and signed SPUK hash. (SHA256)
 * 5. Do SPUK hash, and using the public key to verify the SPUK. (RSA1024)
 * 6. Generate the client DH public key(CPUK) randomly.
 *    and mod it to gen client DH private key (CPRK)
 * 7. Send CPUK to server.
 * 8. Caculate: DHP + SPUK + CPRK = CSK.
 * 9. Recv the server encrypted msg.
 * 10. Decrypt the msg as "hello world."
 * */
int test_rsa_dh_client()
{
    int ret = 0;
    ret = mbedtls_dh_client_entry();
    if (ret != 0) {
        printf("test failed for rsa dh client\n");
        return ret;
    }
}

int test_ecdh_server()
{
    int ret = 0;
    ret = mbedtls_ecdh_server_entry();
    if (ret != 0) {
        printf("test failed for rsa dh server\n");
        return ret;
    }
}

/*
 * Test for rsa hd client.
 * 1. init mbedtls, read (DHP) from dh_prime.txt
 * 2. init network as client.
 * 3. Connect to server network.
 * 4. Recv server's SPUK and signed SPUK hash. (SHA256)
 * 5. Do SPUK hash, and using the public key to verify the SPUK. (RSA1024)
 * 6. Generate the client DH public key(CPUK) randomly.
 *    and mod it to gen client DH private key (CPRK)
 * 7. Send CPUK to server.
 * 8. Caculate: DHP + SPUK + CPRK = CSK.
 * 9. Recv the server encrypted msg.
 * 10. Decrypt the msg as "hello world."
 * */
int test_ecdh_client()
{
    int ret = 0;
    ret = mbedtls_ecdh_client_entry();
    if (ret != 0) {
        printf("test failed for rsa dh client\n");
        return ret;
    }
}

int test_cert_req()
{
    int ret = 0;
    ret = mbedtls_gen_csr_file();
    if (ret != 0) {
        printf("test fialed for cert req\n");
        return ret;
    }
}

int test_cert_crt()
{
    int ret = 0;
    ret = mbedtls_gen_crt_file();
    if (ret != 0) {
        printf("test failed for cert crt\n");
        return ret;
    }
}

int test_sca()
{
    int ret = 0;
    uint8_t plain_buffer[128];
    uint8_t cipher_text[128];
    size_t plain_len = 0;
    size_t cipher_len = 0;
    size_t i = 0;
    const uint8_t key[16] = { 0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b,
                        0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06 };
    const uint8_t iv[16] = { 0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30,
                       0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41 };
    const unsigned char *ptx = "this is the test the sca msg\n";
    cipher_len = sizeof cipher_text;
    ret = openssl_cipher_user_encrypt(ptx, strlen(ptx), iv, sizeof iv,
                                      key, sizeof key ,
                                      cipher_text, &cipher_len,
                                      M_AES_128_CBC);
    if (ret != 0) {
        printf("test failed for user encrypt\n");
        return ret;
    }
    ret = mbedtls_cipher_user_decrypt(cipher_text, cipher_len, iv, sizeof iv,
                                      key, sizeof key,
                                      plain_buffer, &plain_len,
                                      M_AES_128_CBC);
    if (ret != 0) {
        printf("test failed for user decrypt\n");
        return ret;
    }
    plain_buffer[plain_len] = '\0';
    printf("mbedtls plain text : %s\n", plain_buffer);

    ret = mbedtls_cipher_user_encrypt(ptx, strlen(ptx), iv, sizeof iv,
                                      key, sizeof key ,
                                      cipher_text, &cipher_len,
                                      M_AES_128_CBC);
    if (ret != 0) {
        printf("test failed for user encrypt\n");
        return ret;
    }
    ret = openssl_cipher_user_decrypt(cipher_text, cipher_len, iv, sizeof iv,
                                      key, sizeof key,
                                      plain_buffer, &plain_len,
                                      M_AES_128_CBC);
    if (ret != 0) {
        printf("test failed for user decrypt\n");
        return ret;
    }
    plain_buffer[plain_len] = '\0';
    printf("openssl plain text : %s\n", plain_buffer);
}
#endif