
#include <stdio.h>
#include <memory.h>
#include "aes.h"
#include "test_data_aes_ecb.h"
#include "test_data_aes_cbc.h"
#include "test_data_aes_ctr.h"

#ifndef mbedtls_printf
#define mbedtls_printf printf
#endif

int mbedtls_cipher_ecb_enc(void)
{
    int ret = 0;
    mbedtls_aes_context ctx;
    uint8_t result_buf[16] = {0};

    mbedtls_aes_init(&ctx);

    /* encrypt */
    ret = mbedtls_aes_setkey_enc(&ctx, aes_test_ecb_key, 128);
    if (ret != 0) {
        mbedtls_printf("[error 0x%x]: set user key failed.\n", ret);
        return ret;
    }

    ret = mbedtls_aes_crypt_ecb(&ctx,
                                MBEDTLS_AES_ENCRYPT,
                                aes_test_ecb_enc,
                                result_buf);
    if (ret != 0) {
        mbedtls_printf("[error 0x%x]: aes encrypt ecb failed.\n", ret);
        return ret;
    }

    mbedtls_aes_free(&ctx);
    return ret;
}

int mbedtls_cipher_ecb_dec(void)
{
    int ret = 0;
    mbedtls_aes_context ctx;
    uint8_t result_buf[16] = {0};

    mbedtls_aes_init(&ctx);

    /* decrypt */
    ret = mbedtls_aes_setkey_dec(&ctx, aes_test_ecb_key, 128);
    if (ret != 0) {
        mbedtls_printf("[error 0x%x]: set user key failed.\n", ret);
        return ret;
    }

    ret = mbedtls_aes_crypt_ecb(&ctx,
                                MBEDTLS_AES_DECRYPT,
                                aes_test_ecb_dec,
                                result_buf);
    if (ret != 0) {
        mbedtls_printf("[error 0x%x]: aes decrypt ecb failed.\n", ret);
        return ret;
    }

    mbedtls_aes_free(&ctx);
    return ret;
}

int mbedtls_cipher_cbc_enc(void)
{
    int ret = 0;
    mbedtls_aes_context ctx;
    uint8_t result_buf[256] = {0};
    uint8_t iv[16] = {0};

    mbedtls_aes_init(&ctx);

    /* encrypt */
    ret = mbedtls_aes_setkey_enc(&ctx, aes_test_cbc_key, 128);
    if (ret != 0) {
        mbedtls_printf("[error 0x%x]: set user key failed.\n", ret);
        return ret;
    }

    memcpy(iv, aes_test_cbc_iv, sizeof(iv));
    ret = mbedtls_aes_crypt_cbc(&ctx,
                                MBEDTLS_AES_ENCRYPT,
                                sizeof(aes_test_cbc_enc),
                                iv,
                                aes_test_ecb_enc,
                                result_buf);
    if (ret != 0) {
        mbedtls_printf("[error 0x%x]: aes encrypt ecb failed.\n", ret);
        return ret;
    }

    mbedtls_aes_free(&ctx);
    return ret;
}

int mbedtls_cipher_cbc_enc_multi_block(void)
{
    int ret = 0;
    mbedtls_aes_context ctx;
    uint8_t result_buf[256] = {0};
    uint8_t iv[16] = {0};
    uint8_t i = 0;
    uint8_t block_size = 16;

    mbedtls_aes_init(&ctx);

    /* encrypt */
    ret = mbedtls_aes_setkey_enc(&ctx, aes_test_cbc_key, 128);
    if (ret != 0) {
        mbedtls_printf("[error 0x%x]: set user key failed.\n", ret);
        return ret;
    }

    memcpy(iv, aes_test_cbc_iv, sizeof(iv));
    for (i = 0; i < sizeof(result_buf) / block_size; i ++) {
        ret = mbedtls_aes_crypt_cbc(&ctx,
                                    MBEDTLS_AES_ENCRYPT,
                                    block_size,
                                    iv,
                                    aes_test_ecb_enc + i * block_size,
                                    result_buf + i * block_size);
        if (ret != 0) {
            mbedtls_printf("[error 0x%x]: aes encrypt cbc failed.\n", ret);
            return ret;
        }
    }

    mbedtls_aes_free(&ctx);
    return ret;
}

int mbedtls_cipher_cbc_dec(void)
{
    int ret = 0;
    mbedtls_aes_context ctx;
    uint8_t result_buf[256] = {0};
    uint8_t iv[16] = {0};

    mbedtls_aes_init(&ctx);

    /* decrypt */
    ret = mbedtls_aes_setkey_dec(&ctx, aes_test_cbc_key, 128);
    if (ret != 0) {
        mbedtls_printf("[error 0x%x]: set user key failed.\n", ret);
        return ret;
    }

    memcpy(iv, aes_test_cbc_iv, sizeof(iv));
    ret = mbedtls_aes_crypt_cbc(&ctx,
                                MBEDTLS_AES_DECRYPT,
                                sizeof(aes_test_cbc_dec),
                                iv,
                                aes_test_ecb_dec,
                                result_buf);
    if (ret != 0) {
        mbedtls_printf("[error 0x%x]: aes decrypt cbc failed.\n", ret);
        return ret;
    }

    mbedtls_aes_free(&ctx);
    return ret;
}

int mbedtls_cipher_cbc_dec_multi_block(void)
{
    int ret = 0;
    mbedtls_aes_context ctx;
    uint8_t result_buf[256] = {0};
    uint8_t iv[16] = {0};
    uint8_t i = 0;
    uint8_t block_size = 16;

    mbedtls_aes_init(&ctx);

    /* encrypt */
    ret = mbedtls_aes_setkey_dec(&ctx, aes_test_cbc_key, 128);
    if (ret != 0) {
        mbedtls_printf("[error 0x%x]: set user key failed.\n", ret);
        return ret;
    }

    memcpy(iv, aes_test_cbc_iv, sizeof(iv));
    for (i = 0; i < sizeof(result_buf) / block_size; i ++) {
        ret = mbedtls_aes_crypt_cbc(&ctx,
                                    MBEDTLS_AES_DECRYPT,
                                    block_size,
                                    iv,
                                    aes_test_ecb_dec + i * block_size,
                                    result_buf + i * block_size);
        if (ret != 0) {
            mbedtls_printf("[error 0x%x]: aes decrypt cbc failed.\n", ret);
            return ret;
        }
    }

    mbedtls_aes_free(&ctx);
    return ret;
}

int mbedtls_cipher_ctr_enc(void)
{
    int ret = 0;
    mbedtls_aes_context ctx;
    uint8_t result_buf[256] = {0};
    uint8_t nounce_counter[16] = {0};
    uint8_t strblk[16] = {0};
    size_t nc_off = 0;

    mbedtls_aes_init(&ctx);

    /* encrypt */
    ret = mbedtls_aes_setkey_enc(&ctx, aes_test_ctr_key, 128);
    if (ret != 0) {
        mbedtls_printf("[error 0x%x]: set user key failed.\n", ret);
        return ret;
    }

    memcpy(nounce_counter, aes_test_ctr_iv, sizeof(nounce_counter));
    ret = mbedtls_aes_crypt_ctr(&ctx,
                                sizeof(aes_test_ctr_enc),
                                &nc_off,
                                nounce_counter,
                                strblk,
                                aes_test_ecb_enc,
                                result_buf);
    if (ret != 0) {
        mbedtls_printf("[error 0x%x]: aes encrypt ctr failed.\n", ret);
        return ret;
    }

    mbedtls_aes_free(&ctx);
    return ret;
}

int mbedtls_cipher_ctr_enc_multi_block(void)
{
    int ret = 0;
    mbedtls_aes_context ctx;
    uint8_t result_buf[256] = {0};
    uint8_t nounce_counter[16] = {0};
    uint8_t strblk[16] = {0};
    size_t nc_off = 0;
    uint8_t i = 0;
    uint8_t block_size = 16;

    mbedtls_aes_init(&ctx);

    /* encrypt */
    ret = mbedtls_aes_setkey_enc(&ctx, aes_test_cbc_key, 128);
    if (ret != 0) {
        mbedtls_printf("[error 0x%x]: set user key failed.\n", ret);
        return ret;
    }

    memcpy(nounce_counter, aes_test_cbc_iv, sizeof(nounce_counter));
    for (i = 0; i < sizeof(result_buf) / block_size; i ++) {
        ret = mbedtls_aes_crypt_ctr(&ctx,
                                    block_size,
                                    &nc_off,
                                    nounce_counter,
                                    strblk,
                                    aes_test_ecb_enc + i * block_size,
                                    result_buf + i * block_size);
        if (ret != 0) {
            mbedtls_printf("[error 0x%x]: aes encrypt ctr failed.\n", ret);
            return ret;
        }
    }

    mbedtls_aes_free(&ctx);
    return ret;
}

int mbedtls_cipher_ctr_dec(void)
{
    int ret = 0;
    mbedtls_aes_context ctx;
    uint8_t result_buf[256] = {0};
    uint8_t nounce_counter[16] = {0};
    uint8_t strblk[16] = {0};
    size_t nc_off = 0;

    mbedtls_aes_init(&ctx);

    /* decrypt */
    ret = mbedtls_aes_setkey_dec(&ctx, aes_test_ctr_key, 128);
    if (ret != 0) {
        mbedtls_printf("[error 0x%x]: set user key failed.\n", ret);
        return ret;
    }

    memcpy(nounce_counter, aes_test_ctr_iv, sizeof(nounce_counter));
    ret = mbedtls_aes_crypt_ctr(&ctx,
                                sizeof(aes_test_ctr_dec),
                                &nc_off,
                                nounce_counter,
                                strblk,
                                aes_test_ecb_dec,
                                result_buf);
    if (ret != 0) {
        mbedtls_printf("[error 0x%x]: aes decrypt ctr failed.\n", ret);
        return ret;
    }

    mbedtls_aes_free(&ctx);
    return ret;
}

int mbedtls_cipher_ctr_dec_multi_block(void)
{
    int ret = 0;
    mbedtls_aes_context ctx;
    uint8_t result_buf[256] = {0};
    uint8_t nounce_counter[16] = {0};
    uint8_t strblk[16] = {0};
    size_t nc_off = 0;
    uint8_t i = 0;
    uint8_t block_size = 16;

    mbedtls_aes_init(&ctx);

    /* decrypt */
    ret = mbedtls_aes_setkey_dec(&ctx, aes_test_cbc_key, 128);
    if (ret != 0) {
        mbedtls_printf("[error 0x%x]: set user key failed.\n", ret);
        return ret;
    }

    memcpy(nounce_counter, aes_test_cbc_iv, sizeof(nounce_counter));
    for (i = 0; i < sizeof(result_buf) / block_size; i ++) {
        ret = mbedtls_aes_crypt_ctr(&ctx,
                                    block_size,
                                    &nc_off,
                                    nounce_counter,
                                    strblk,
                                    aes_test_ecb_dec + i * block_size,
                                    result_buf + i * block_size);
        if (ret != 0) {
            mbedtls_printf("[error 0x%x]: aes decrypt ctr failed.\n", ret);
            return ret;
        }
    }

    mbedtls_aes_free(&ctx);
    return ret;
}