//
// Created by 魏昊晨 on 2020/9/5.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "openssl_md_sha.h"
/*open ssl MD5 using*/
int openssl_md5(unsigned char *content, uint64_t len, unsigned char *out)
{
#define OK	1
    MD5_CTX ctx;
    unsigned char outmd[32];
    uint16_t i = 0;
    int ret = 0;

    if (content == NULL || out == NULL) {
        ret = -1;
        printf("input || output string is NULL.\n");
        return ret;
    }
    memset(outmd, 0, sizeof(outmd));
    ret = MD5_Init(&ctx);
    if (ret != OK) {
        printf("MD5_INIT Failed, ret=%d\n", ret);
        return ret;
    }
    ret = MD5_Update(&ctx, content, len);
    if (ret != OK) {
        printf("MD5_Update Failed, ret=%d\n", ret);
        return ret;
    }
    ret = MD5_Final(outmd, &ctx);
    if (ret != OK) {
        printf("MD5_Update Failed, ret=%d\n", ret);
        return ret;
    }
    ret = 0;
    memcpy(out, outmd, 16);
    return ret;
}

/*open ssl evp MD5 using*/
int openssl_evp_md5(unsigned char *content, uint64_t len, unsigned char *out)
{
#define EVP_OK	1
    EVP_MD_CTX *evp_ctx = NULL;
    unsigned char outmd[32];
    int md_len = 0;
    int i = 0;
    int ret = 0;

    if (content == NULL || out == NULL) {
        ret = -1;
        printf("input || output string is NULL.\n");
        return ret;
    }
    evp_ctx = EVP_MD_CTX_new();
    if (evp_ctx == NULL) {
        printf("EVP_CIPHER_CTX_new failed.\n");
        ret = -1;
        return ret;
    }
    memset(outmd, 0, 16);
    EVP_MD_CTX_init(evp_ctx);
    ret = EVP_DigestInit_ex(evp_ctx, EVP_md5(), NULL);
    if (ret != EVP_OK) {
        EVP_MD_CTX_free(evp_ctx);
        printf("EVP_DigestInit_ex Failed, ret=%d\n", ret);
        return ret;
    }
    ret = EVP_DigestUpdate(evp_ctx, content, len);
    if (ret != EVP_OK) {
        EVP_MD_CTX_free(evp_ctx);
        printf("EVP_DigestUpdate Failed, ret=%d\n", ret);
        return ret;
    }
    ret = EVP_DigestFinal_ex(evp_ctx, outmd, &md_len);
    if (ret != EVP_OK) {
        EVP_MD_CTX_free(evp_ctx);
        printf("EVP_DigestFinal_ex Failed, ret=%d\n", ret);
        return ret;
    }
    EVP_MD_CTX_free(evp_ctx);
    memcpy(out, outmd, md_len);
    ret = 0;
    return ret;
}