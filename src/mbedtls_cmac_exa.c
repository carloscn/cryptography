//
// Created by carwei01 on 2021/6/11.
//
#include "mbedtls_cmac_exa.h"

int mbedtls_cmac_aes_128_ecb(const unsigned char *key, size_t key_byte_size,
                             const unsigned char *input, size_t input_byte_size,
                             unsigned char *output, size_t *output_byte_size)
{
    int rc = 0;     /* mbedtls layer error code */
    int ret = 0;    /* current layer error code */
    mbedtls_cipher_context_t ctx, *p_ctx = NULL;
    mbedtls_cipher_info_t *info = NULL;
    if (key == NULL || input == NULL || output == NULL || output_byte_size == NULL) {
        ret = ERROR_COMMON_INPUT_PARAMETERS;
        mbedtls_printf(" * input parameters error, returned %d, line: %d\n",
                       ret, __LINE__);
        goto finish;
    }
    if (key_byte_size == 0 || input_byte_size == 0) {
        ret = ERROR_NONE;
        mbedtls_printf(" * key size or input size == 0, returned %d, line: %d\n",
                       ret, __LINE__);
        goto finish;
    }
    mbedtls_cipher_init(&ctx);
    p_ctx = &ctx;
    info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    rc = mbedtls_cipher_setup(p_ctx, info);
    if (0 != rc) {
        ret = ERROR_CRYPTO_INIT_FAILED;
        mbedtls_printf(" * cmac cipher init failed, returned 0x%x, line: %d\n",
                       -rc, __LINE__);
        goto finish;
    }
    rc = mbedtls_cipher_cmac_starts(p_ctx, key, BYTE_CONV_BITS_NUM(key_byte_size));
    if (0 != rc) {
        ret = ERROR_CRYPTO_INIT_FAILED;
        mbedtls_printf(" * cmac cipher start failed, returned 0x%x, line: %d\n",
                       -rc, __LINE__);
        goto finish;
    }
    rc = mbedtls_cipher_cmac_update(p_ctx, input, input_byte_size);
    if (0 != rc) {
        ret = ERROR_CRYPTO_ENCRYPT_FAILED;
        mbedtls_printf(" * cmac cipher update failed, returned %d, line: %d\n",
                       rc, __LINE__);
        goto finish;
    }
    rc = mbedtls_cipher_cmac_finish(p_ctx, output);
    if (0 != rc) {
        ret = ERROR_CRYPTO_ENCRYPT_FAILED;
        mbedtls_printf(" * cmac cipher finish failed, returned %d, line: %d\n",
                       rc, __LINE__);
        goto finish;
    }
    *output_byte_size = mbedtls_cipher_get_key_bitlen(p_ctx)/8;

    finish:
    if (NULL != p_ctx) {
        mbedtls_cipher_free(p_ctx);
    }
    return ret;
}
int mbedtls_cmac_aes_192_ecb(const unsigned char *key, size_t key_byte_size,
                             const unsigned char *input, size_t input_byte_size,
                             unsigned char *output, size_t *output_byte_size)
{
    int rc = 0;     /* mbedtls layer error code */
    int ret = 0;    /* current layer error code */
    mbedtls_cipher_context_t ctx, *p_ctx = NULL;
    mbedtls_cipher_info_t *info = NULL;
    if (key == NULL || input == NULL || output == NULL || output_byte_size == NULL) {
        ret = ERROR_COMMON_INPUT_PARAMETERS;
        mbedtls_printf(" * input parameters error, returned %d, line: %d\n",
                       ret, __LINE__);
        goto finish;
    }
    if (key_byte_size == 0 || input_byte_size == 0) {
        ret = ERROR_NONE;
        mbedtls_printf(" * key size or input size == 0, returned %d, line: %d\n",
                       ret, __LINE__);
        goto finish;
    }
    mbedtls_cipher_init(&ctx);
    p_ctx = &ctx;
    info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_ECB);
    rc = mbedtls_cipher_setup(p_ctx, info);
    if (0 != rc) {
        ret = ERROR_CRYPTO_INIT_FAILED;
        mbedtls_printf(" * cmac cipher init failed, returned 0x%x, line: %d\n",
                       -rc, __LINE__);
        goto finish;
    }
    rc = mbedtls_cipher_cmac_starts(p_ctx, key, BYTE_CONV_BITS_NUM(key_byte_size));
    if (0 != rc) {
        ret = ERROR_CRYPTO_INIT_FAILED;
        mbedtls_printf(" * cmac cipher start failed, returned 0x%x, line: %d\n",
                       -rc, __LINE__);
        goto finish;
    }
    rc = mbedtls_cipher_cmac_update(p_ctx, input, input_byte_size);
    if (0 != rc) {
        ret = ERROR_CRYPTO_ENCRYPT_FAILED;
        mbedtls_printf(" * cmac cipher update failed, returned %d, line: %d\n",
                       rc, __LINE__);
        goto finish;
    }
    rc = mbedtls_cipher_cmac_finish(p_ctx, output);
    if (0 != rc) {
        ret = ERROR_CRYPTO_ENCRYPT_FAILED;
        mbedtls_printf(" * cmac cipher finish failed, returned %d, line: %d\n",
                       rc, __LINE__);
        goto finish;
    }
    *output_byte_size = mbedtls_cipher_get_key_bitlen(p_ctx)/8;

    finish:
    if (NULL != p_ctx) {
        mbedtls_cipher_free(p_ctx);
    }
    return ret;
}