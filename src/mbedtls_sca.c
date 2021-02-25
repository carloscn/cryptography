//
// Created by carlos on 2021/2/22.
//

#include "mbedtls_sca.h"

static const unsigned int sca_type_list[] = {
        MBEDTLS_CIPHER_AES_128_CBC,
        MBEDTLS_CIPHER_AES_128_ECB,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_AES_128_CFB128,
        MBEDTLS_CIPHER_AES_128_OFB,
        MBEDTLS_CIPHER_AES_128_CTR,
        MBEDTLS_CIPHER_AES_128_CCM,
        MBEDTLS_CIPHER_AES_128_GCM,
        MBEDTLS_CIPHER_AES_128_XTS,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_AES_192_ECB,
        MBEDTLS_CIPHER_AES_192_CBC,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_AES_192_CFB128,
        MBEDTLS_CIPHER_AES_192_OFB,
        MBEDTLS_CIPHER_AES_192_CTR,
        MBEDTLS_CIPHER_AES_192_CCM,
        MBEDTLS_CIPHER_AES_192_GCM,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_AES_256_ECB,
        MBEDTLS_CIPHER_AES_256_CBC,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_AES_256_CFB128,
        MBEDTLS_CIPHER_AES_256_OFB,
        MBEDTLS_CIPHER_AES_256_CTR,
        MBEDTLS_CIPHER_AES_256_CCM,
        MBEDTLS_CIPHER_AES_256_GCM,
        MBEDTLS_CIPHER_AES_256_XTS,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_ARIA_128_ECB,
        MBEDTLS_CIPHER_ARIA_128_CBC,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_ARIA_128_CFB128,
        MBEDTLS_CIPHER_ARIA_128_CTR,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_ARIA_128_GCM,
        MBEDTLS_CIPHER_ARIA_128_CCM,
        MBEDTLS_CIPHER_ARIA_192_ECB,
        MBEDTLS_CIPHER_ARIA_192_CBC,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_ARIA_192_CFB128,
        MBEDTLS_CIPHER_ARIA_192_CTR,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_ARIA_192_GCM,
        MBEDTLS_CIPHER_ARIA_192_CCM,
        MBEDTLS_CIPHER_ARIA_256_ECB,
        MBEDTLS_CIPHER_ARIA_256_CBC,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_ARIA_256_CFB128,
        MBEDTLS_CIPHER_ARIA_256_CTR,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_ARIA_256_GCM,
        MBEDTLS_CIPHER_ARIA_256_CCM,
        MBEDTLS_CIPHER_CAMELLIA_128_ECB,
        MBEDTLS_CIPHER_CAMELLIA_128_CBC,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_CAMELLIA_128_CFB128,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_CAMELLIA_128_CTR,
        MBEDTLS_CIPHER_CAMELLIA_192_ECB,
        MBEDTLS_CIPHER_CAMELLIA_192_CBC,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_CAMELLIA_192_CFB128,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_CAMELLIA_192_CTR,
        MBEDTLS_CIPHER_CAMELLIA_256_ECB,
        MBEDTLS_CIPHER_CAMELLIA_256_CBC,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_CAMELLIA_256_CFB128,
        MBEDTLS_CIPHER_NONE,
        MBEDTLS_CIPHER_CAMELLIA_256_CTR,
        MBEDTLS_CIPHER_CHACHA20,
        MBEDTLS_CIPHER_CHACHA20_POLY1305
};

/* Using the mbedtls cipher interface to encrypt the msg */

int mbedtls_cipher_user_encrypt(const unsigned char* plain_text, size_t plain_len,
                                const unsigned char* iv, size_t iv_len,
                                const unsigned char* key, size_t key_len,
                                unsigned char *out_buffer, size_t *out_len, int aes_type)
{
    int ret = ERROR_NONE;
    int rc = MBEDTLS_EXIT_SUCCESS;
    mbedtls_printf("\nmbedtls_cipher_encrypt data.\n");
    if (plain_text == NULL || plain_len == 0 ||
        out_buffer == NULL || out_len == NULL ||
        iv == NULL || iv_len == 0 ||
        key == NULL || key_len == 0) {
        mbedtls_printf(" * input parameter(s) is invalid\n");
        ret = ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    mbedtls_cipher_type_t type;
    /* Current type just support up to POLY1305(max) */
    if (aes_type > ARRAY_SIZE(sca_type_list)) {
        mbedtls_printf(" * input type is not supported on mbedtls. \n");
        ret = ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    type = (mbedtls_cipher_type_t)sca_type_list[aes_type];
    if (type == MBEDTLS_CIPHER_NONE) {
        mbedtls_printf(" * input type is not supported on mbedtls %d\n", type);
        ret = ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    size_t olen = 0, len = 0;
    mbedtls_cipher_context_t ctx;
    const mbedtls_cipher_info_t *info = NULL;
    mbedtls_cipher_init(&ctx);
    /*
     * The type enum define in the mbedtls/cipher.h file.
     * 1. MBEDTLS_CIPHER_AES_128_CBC
     * 2. MBEDTLS_CIPHER_AES_192_CTR
     * 3. etc...
     * */
    info = mbedtls_cipher_info_from_type(type);
    if (info == NULL) {
        mbedtls_printf(" * mbedtls_cipher_get_info error. line: %d\n", __LINE__);
        ret = ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    rc = mbedtls_cipher_setup(&ctx, info);
    if (rc != 0) {
        mbedtls_printf(" * mbedtls_cipher_setup failed, returned %d, line: %d\n",
                       rc, __LINE__);
        ret = ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    mbedtls_printf(" * cipher info setup \n"
                   " * name: %s\n"
                   " * block size: %zd\n",
                   mbedtls_cipher_get_name(&ctx),
                   mbedtls_cipher_get_block_size(&ctx)
    );
    mbedtls_printf(" *\n"
                   " * cipher start set key.\n"
    );
    rc = mbedtls_cipher_setkey(&ctx, key, key_len*8, MBEDTLS_ENCRYPT);
    if (rc != 0) {
        mbedtls_printf(" * mbedtls_cipher_setkey failed, returned %d, line: %d\n",
                       rc, __LINE__);
        ret = ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    mbedtls_printf(" *\n"
                   " * cipher start set iv.\n"
    );
    rc = mbedtls_cipher_set_iv(&ctx, iv, iv_len);
    if (rc != 0) {
        mbedtls_printf(" * mbedtls_cipher_set_iv failed, returned %d, line: %d\n",
                       rc, __LINE__);
        ret = ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    mbedtls_printf(" *\n"
                   " * cipher load plain text.\n"
    );
    /*
     * mbedtls_cipher_update return the length is not aligned part.
     * and the others part will return on cipher_finish finishing.
     * */
    *out_len = 0;
    rc = mbedtls_cipher_update(&ctx, plain_text, plain_len, out_buffer, &len);
    if (rc != 0) {
        mbedtls_printf(" * mbedtls_cipher_update failed, returned %d, line: %d\n",
                       rc, __LINE__);
        ret = ERROR_CRYPTO_ENCRYPT_FAILED;
        goto finish;
    }
    *out_len += len;
    rc = mbedtls_cipher_finish(&ctx, out_buffer + len, &len);
    if (rc != 0) {
        mbedtls_printf(" * mbedtls_cipher_finish failed, returned %d, line: %d\n",
                       rc, __LINE__);
        ret = ERROR_CRYPTO_ENCRYPT_FAILED;
        goto finish;
    }
    *out_len += len;
    mbedtls_printf(" * finish cipher. cipher len: %d\n", *out_len);

    finish:
    mbedtls_cipher_free(&ctx);
    mbedtls_printf("finish mbedtls_cipher_encrypt.\n\n");
    return ret;
}

int mbedtls_cipher_user_decrypt(const unsigned char* cipher_text, size_t cipher_len,
                                const unsigned char* iv, size_t iv_len,
                                const unsigned char* key, size_t key_len,
                                unsigned char *out_buffer, size_t *out_len, int aes_type)
{
    int ret = ERROR_NONE;
    int rc = MBEDTLS_EXIT_SUCCESS;
    mbedtls_printf("\nmbedtls_cipher_decrypt data.\n");
    if (cipher_text == NULL || cipher_len == 0 ||
        out_buffer == NULL || out_len == NULL ||
        iv == NULL || iv_len == 0 ||
        key == NULL || key_len == 0) {
        mbedtls_printf(" * input parameter(s) is invalid\n");
        ret = ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    mbedtls_cipher_type_t type;
    /* Current type just support up to POLY1305(max) */
    if (aes_type > ARRAY_SIZE(sca_type_list)) {
        mbedtls_printf(" * input type is not supported. \n");
        ret = ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    type = (mbedtls_cipher_type_t)sca_type_list[aes_type];
    if (type == MBEDTLS_CIPHER_NONE) {
        mbedtls_printf(" * input type is not supported. %d\n", type);
        ret = ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    size_t olen = 0, len = 0;
    mbedtls_cipher_context_t ctx;
    const mbedtls_cipher_info_t *info = NULL;

    mbedtls_cipher_init(&ctx);
    /*
     * The type enum define in the mbedtls/cipher.h file.
     * 1. MBEDTLS_CIPHER_AES_128_CBC
     * 2. MBEDTLS_CIPHER_AES_192_CTR
     * 3. etc...
     * */
    info = mbedtls_cipher_info_from_type(type);
    if (info == NULL) {
        mbedtls_printf(" * mbedtls_cipher_get_info error. line: %d\n", __LINE__);
        ret = ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    rc = mbedtls_cipher_setup(&ctx, info);
    if (rc != 0) {
        mbedtls_printf(" * mbedtls_cipher_setup failed, returned %d, line: %d\n",
                       rc, __LINE__);
        ret = ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    mbedtls_printf(" * cipher info setup \n"
                   " * name: %s\n"
                   " * block size: %zd\n",
                   mbedtls_cipher_get_name(&ctx),
                   mbedtls_cipher_get_block_size(&ctx)
    );
    mbedtls_printf(" *\n"
                   " * cipher start set key.\n"
    );
    rc = mbedtls_cipher_setkey(&ctx, key, key_len*8, MBEDTLS_DECRYPT);
    if (rc != 0) {
        mbedtls_printf(" * mbedtls_cipher_setkey failed, returned %d, line: %d\n",
                       rc, __LINE__);
        ret = ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    mbedtls_printf(" *\n"
                   " * cipher start set iv.\n"
    );
    rc = mbedtls_cipher_set_iv(&ctx, iv, iv_len);
    if (rc != 0) {
        mbedtls_printf(" * mbedtls_cipher_set_iv failed, returned %d, line: %d\n",
                       rc, __LINE__);
        ret = ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    mbedtls_printf(" *\n"
                   " * cipher load plain text.\n"
    );
    /*
     * mbedtls_cipher_update return the length is not aligned part.
     * and the others part will return on cipher_finish finishing.
     * */
    *out_len = 0;
    rc = mbedtls_cipher_update(&ctx, cipher_text, cipher_len, out_buffer, &len);
    if (rc != 0) {
        mbedtls_printf(" * mbedtls_cipher_update failed, returned %d, line: %d\n",
                       rc, __LINE__);
        ret = ERROR_CRYPTO_DECRYPT_FAILED;
        goto finish;
    }
    *out_len += len;
    rc = mbedtls_cipher_finish(&ctx, out_buffer + len, &len);
    if (rc != 0) {
        mbedtls_printf(" * mbedtls_cipher_finish failed, returned %d, line: %d\n",
                       rc, __LINE__);
        ret = ERROR_CRYPTO_DECRYPT_FAILED;
        goto finish;
    }
    *out_len += len;
    mbedtls_printf(" * finish cipher. cipher len: %d\n", *out_len);

    finish:
    mbedtls_cipher_free(&ctx);
    mbedtls_printf("finish mbedtls_cipher_decrypt.\n\n");
    return ret;
}