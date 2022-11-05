#include "mbedtls_hmac.h"

int mbedtls_hmac_sha384(const unsigned char *key,
                        size_t key_byte_size,
                        const unsigned char *input,
                        size_t input_byte_size,
                        unsigned char output[48])
{

    int ret = 0, mret = 0;
    mbedtls_md_info_t *info = NULL;
    mbedtls_md_context_t ctx;

    if (key == NULL ||
        input == NULL ||
        output == NULL) {
        ret = ERROR_COMMON_INPUT_PARAMETERS;
        mbedtls_printf(" * input parameters error, returned %d, line: %d\n",
                       ret, __LINE__);
        goto finish;
    }

    if (key_byte_size == 0 ||
        input_byte_size == 0) {
        ret = ERROR_NONE;
        mbedtls_printf(" * key size or input size == 0, returned %d, line: %d\n",
                       ret, __LINE__);
        goto finish;
    }

    mbedtls_md_init(&ctx);

    info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
    if (NULL == info) {
        ret = ERROR_CRYPTO_INIT_FAILED;
        mbedtls_printf(" * init failed, returned %d, line: %d\n",
                       ret, __LINE__);
        goto ctx_inited;
    }

    mret = mbedtls_md_setup(&ctx, info, 1);
    if (0 != mret) {
        ret = ERROR_CRYPTO_INIT_FAILED;
        mbedtls_printf(" * init failed, returned %d, line: %d\n",
                       ret, __LINE__);
        goto ctx_inited;
    }

    mret = mbedtls_md_hmac_starts(&ctx, key, key_byte_size);
    if (0 != mret) {
        ret = ERROR_CRYPTO_INIT_FAILED;
        mbedtls_printf(" * start failed, returned %d, line: %d\n",
                       ret, __LINE__);
        goto ctx_inited;
    }

    mret = mbedtls_md_hmac_update(&ctx, input, input_byte_size);
    if (0 != mret) {
        ret = ERROR_CRYPTO_ENCRYPT_FAILED;
        mbedtls_printf(" * update failed, returned %d, line: %d\n",
                       ret, __LINE__);
        goto ctx_inited;
    }

    mret = mbedtls_md_hmac_finish(&ctx, output);
    if (0 != mret) {
        ret = ERROR_CRYPTO_ENCRYPT_FAILED;
        mbedtls_printf(" * finish failed, returned %d, line: %d\n",
                       ret, __LINE__);
    }

ctx_inited:
    mbedtls_md_free(&ctx);
finish:
    return ret;
}