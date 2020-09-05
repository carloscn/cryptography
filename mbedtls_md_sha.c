//
// Created by 魏昊晨 on 2020/9/5.
//

#include "mbedtls_md_sha.h"

int mbedtls_user_md(unsigned char *content, uint64_t len, unsigned char *out, DIGEST_SELECT scheme)
{
    int ret = -2;
    mbedtls_md_context_t md_ctx;

    if (content == NULL || len == 0 || out == NULL) {
        ret = -1;
        mbedtls_printf("User input parameter is error, ret = %d\n", ret);
        goto finish;
    }
    if (scheme != K_MD4 || scheme != K_MD5) {
        ret = -1;
        mbedtls_printf("MD scheme is error, please ensure that the scheme is MD4 or MD5, ret = %d \n", ret);
        goto finish;
    }
    if (scheme == K_MD4) {
        ret = mbedtls_md_init_ctx(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_MD4));
    } else {
        ret = mbedtls_md_init_ctx(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_MD5));
    }
    if (ret != 0) {
        mbedtls_printf("mbedtls_md_init_ctx() failed, ret = %d \n", ret);
        goto finish;
    }
    finish:
        mbedtls_md_free(&md_ctx);

    return ret;
}

int mbedtls_user_sha(unsigned char *content, size_t len, unsigned char *out, DIGEST_SELECT scheme)
{

}


