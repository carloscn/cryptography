//
// Created by 魏昊晨 on 2020/9/5.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "unit_test.h"

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
    ret = mbedtls_user_md(input_str, strlen(input_str), outmd,  "MD5");
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
    ret = openssl_evp_pkcs1_rsa_signature(plain_in, in_len, sign_out, &out_len, RSA_SHA256,
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

    ret = openssl_evp_pkcs1_rsa_verify(sign_out, out_len, plain_in, in_len, RSA_SHA256,
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
    ret = openssl_evp_pkcs8_rsa_signature(plain_in, in_len, sign_out, &out_len, RSA_SHA256,
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

    ret = openssl_evp_pkcs8_rsa_verify(sign_out, out_len, plain_in, in_len, RSA_SHA256,
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

int mbedtls_test_ecc_sign_verfiy()
{
    int ret = 0, i = 0;
    unsigned char sign_out[1024];
    unsigned char plain_in[] = "hello carlos.";
    size_t out_len = 256;
    size_t in_len = strlen(plain_in);

    ret = mbedtls_ecdsa_signature(plain_in, in_len, sign_out, &out_len, PRIVATE_ECC_KEY_FILE, NULL);
    if (ret != 0) {
        printf("mbedtls ecc signature failed!\n");
        return ret;
    }
    printf("ecc %s mbedtls sign len = %ld, signature result: \n", plain_in, out_len);
    for(i = 0; i < out_len; i++) {
        printf("%02X", sign_out[i]);
    }
    printf("\n");

    ret = mbedtls_ecdsa_verified(sign_out, out_len, plain_in, in_len, PUBLIC_ECC_KEY_FILE);
    if (ret != 0) {
        printf("mbedtls ecc verify failed!\n");
    } else {
        printf("mbedtls ecc verify succeed!\n");
    }
}
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
