//
// Created by 魏昊晨 on 2020/9/5.
//

#include "mbedtls_md_sha.h"
#include "utils.h"

/*
 * init(setup) -> starts -> update 1-> update n-> ... -> finish.
 * */
int mbedtls_user_md(unsigned char *content, uint64_t len, unsigned char *out, const char *type)
{
    int ret = -2;
    mbedtls_md_context_t md_ctx;

    if (content == NULL || len == 0 || out == NULL) {
        ret = -1;
        mbedtls_printf("User input parameter is error, ret = %d\n", ret);
        goto finish;
    }
    // 1) init method one:
    // ->this interface call the mbedtls_md_setup(ctx, md_info, 1) and give the parameter
    // -->hmac = 1. if you want to disable the hmac, need recall the mbedtls_md_setup(ctx, md_info, 0)
    // --->in fact, hmac parameter no effect on md5 caculation.
    //ret = mbedtls_md_init_ctx(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_MD5));
    // ->or you can set md from string "MD5" is same effect.
    // -->ret = mbedtls_md_init_ctx(&md_ctx, mbedtls_md_info_from_string("MD5"));

    // 2) init method two:
    // ->hmac parameter no effect.
    mbedtls_md_init(&md_ctx);
    ret = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_string(type), 0);
    if (ret != 0) {
        mbedtls_printf("mbedtls_md_init_ctx() failed, ret = %d \n", ret);
        goto finish;
    }
    // ->|init finish.|<-
    ret = mbedtls_md_starts(&md_ctx);
    if (ret != 0) {
        mbedtls_printf("mbedtls_md_init_ctx() failed, ret = %d \n", ret);
        goto finish;
    }
    // ->|start finish.|<-
    ret = mbedtls_md_update(&md_ctx, content, len);
    if (ret != 0) {
        mbedtls_printf("mbedtls_md_update() failed, ret = %d \n", ret);
        goto finish;
    }
    // ->|update finish.|<-
    ret = mbedtls_md_finish(&md_ctx, out);
    if (ret != 0) {
        mbedtls_printf("mbedtls_md_finish() failed, ret = %d \n", ret);
        goto finish;
    }
    // ->|finish finish.|<-
    finish:
        mbedtls_md_free(&md_ctx);
    return ret;
}