//
// Created by carlos on 2021/2/23.
//
#include "openssl_sca.h"

static const EVP_CIPHER* sca_type_list[] = {
    EVP_aes_128_cbc,
    EVP_aes_128_ecb,
    EVP_aes_128_cfb1,
    EVP_aes_128_cfb8,
    EVP_aes_128_cfb128,
    EVP_aes_128_ofb,
    EVP_aes_128_ctr,
    EVP_aes_128_ccm,
    EVP_aes_128_gcm,
    EVP_aes_128_xts,
    EVP_aes_128_wrap,
    EVP_aes_128_wrap_pad,
    EVP_aes_128_ocb,
    EVP_aes_192_ecb,
    EVP_aes_192_cbc,
    EVP_aes_192_cfb1,
    EVP_aes_192_cfb8,
    EVP_aes_192_cfb128,
    EVP_aes_192_ofb,
    EVP_aes_192_ctr,
    EVP_aes_192_ccm,
    EVP_aes_192_gcm,
    EVP_aes_192_wrap,
    EVP_aes_192_wrap_pad,
    EVP_aes_192_ocb,
    EVP_aes_256_ecb,
    EVP_aes_256_cbc,
    EVP_aes_256_cfb1,
    EVP_aes_256_cfb8,
    EVP_aes_256_cfb128,
    EVP_aes_256_ofb,
    EVP_aes_256_ctr,
    EVP_aes_256_ccm,
    EVP_aes_256_gcm,
    EVP_aes_256_xts,
    EVP_aes_256_wrap,
    EVP_aes_256_wrap_pad,
    EVP_aes_256_ocb,
    EVP_aes_128_cbc_hmac_sha1,
    EVP_aes_256_cbc_hmac_sha1,
    EVP_aes_128_cbc_hmac_sha256,
    EVP_aes_256_cbc_hmac_sha256,
    EVP_aria_128_ecb,
    EVP_aria_128_cbc,
    EVP_aria_128_cfb1,
    EVP_aria_128_cfb8,
    EVP_aria_128_cfb128,
    EVP_aria_128_ctr,
    EVP_aria_128_ofb,
    EVP_aria_128_gcm,
    EVP_aria_128_ccm,
    EVP_aria_192_ecb,
    EVP_aria_192_cbc,
    EVP_aria_192_cfb1,
    EVP_aria_192_cfb8,
    EVP_aria_192_cfb128,
    EVP_aria_192_ctr,
    EVP_aria_192_ofb,
    EVP_aria_192_gcm,
    EVP_aria_192_ccm,
    EVP_aria_256_ecb,
    EVP_aria_256_cbc,
    EVP_aria_256_cfb1,
    EVP_aria_256_cfb8,
    EVP_aria_256_cfb128,
    EVP_aria_256_ctr,
    EVP_aria_256_ofb,
    EVP_aria_256_gcm,
    EVP_aria_256_ccm,
    EVP_camellia_128_ecb,
    EVP_camellia_128_cbc,
    EVP_camellia_128_cfb1,
    EVP_camellia_128_cfb8,
    EVP_camellia_128_cfb128,
    EVP_camellia_128_ofb,
    EVP_camellia_128_ctr,
    EVP_camellia_192_ecb,
    EVP_camellia_192_cbc,
    EVP_camellia_192_cfb1,
    EVP_camellia_192_cfb8,
    EVP_camellia_192_cfb128,
    EVP_camellia_192_ofb,
    EVP_camellia_192_ctr,
    EVP_camellia_256_ecb,
    EVP_camellia_256_cbc,
    EVP_camellia_256_cfb1,
    EVP_camellia_256_cfb8,
    EVP_camellia_256_cfb128,
    EVP_camellia_256_ofb,
    EVP_camellia_256_ctr,
    EVP_chacha20,
    EVP_chacha20_poly1305
};

int openssl_cipher_user_encrypt(const unsigned char* plain_text, size_t plain_len,
                                const unsigned char* iv, size_t iv_len,
                                const unsigned char* key, size_t key_len,
                                unsigned char *out_buffer, size_t *out_len, int aes_type)
{
    int ret = ERROR_NONE;
    int rc = OPSSL_OK;
    printf("\nopenssl_cipher_encrypt data.\n");
    if (plain_text == NULL || plain_len == 0 ||
        out_buffer == NULL || out_len == NULL ||
        iv == NULL || iv_len == 0 ||
        key == NULL || key_len == 0) {

        printf(" * input parameter(s) is invalid\n");
        ret = ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    size_t olen = 0, len = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    if (aes_type > ARRAY_SIZE(sca_type_list)) {
        printf(" * the sca type is not supported on openssl.\n");
        ret = ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    EVP_CIPHER* (*type)(void) = sca_type_list[aes_type];
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        printf(" * EVP_CIPHER_CTX new error. line: %d\n", __LINE__);
        ret = ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    rc = EVP_EncryptInit_ex(ctx, type(), NULL, key, iv);
    if (rc != OPSSL_OK) {
        printf(" * EVP_EncryptInit failed. line: %d\n", __LINE__);
        ret = ERROR_CRYPTO_ENCRYPT_FAILED;
        goto finish;
    }
    *out_len = 0;
    rc = EVP_EncryptUpdate(ctx, out_buffer, &len, plain_text, plain_len);
    if (rc != OPSSL_OK) {
        printf(" * EVP_EncryptUpdate failed. line: %d\n", __LINE__);
        ret = ERROR_CRYPTO_ENCRYPT_FAILED;
        goto finish;
    }
    *out_len += len;
    rc = EVP_EncryptFinal_ex(ctx, out_buffer + len, &len);
    if (rc != OPSSL_OK) {
        printf(" * EVP_EncryptFinal failed. line: %d\n", __LINE__);
        ret = ERROR_CRYPTO_ENCRYPT_FAILED;
        goto finish;
    }
    *out_len += len;

    finish:
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);
    printf("OPENSSL ENCRYPT FINISH. len = %d\n", *out_len);
    return ret;
}

int openssl_cipher_user_decrypt(const unsigned char* cipher_text, size_t cipher_len,
                                const unsigned char* iv, size_t iv_len,
                                const unsigned char* key, size_t key_len,
                                unsigned char *out_buffer, size_t *out_len, int aes_type)
{
    int ret = ERROR_NONE;
    int rc = OPSSL_OK;
    printf("\nopenssl_cipher_decrypt data.\n");
    if (cipher_text == NULL || cipher_len == 0 ||
        out_buffer == NULL || out_len == NULL ||
        iv == NULL || iv_len == 0 ||
        key == NULL || key_len == 0) {

        printf(" * input parameter(s) is invalid\n");
        ret = ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    size_t olen = 0, len = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    if (aes_type > ARRAY_SIZE(sca_type_list)) {
        printf(" * the sca type is not supported on openssl.\n");
        ret = ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    const EVP_CIPHER* (*type)(void) = sca_type_list[aes_type];

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        printf(" * EVP_CIPHER_CTX new error. line: %d\n", __LINE__);
        ret = ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    //rc = EVP_DecryptInit_ex(ctx, (const EVP_CIPHER *)EVP_aes_128_cbc(), NULL, key, iv);
    rc = EVP_DecryptInit_ex(ctx, type(), NULL, key, iv);
    if (rc != OPSSL_OK) {
        printf(" * EVP_DecrytInit failed. line: %d\n", __LINE__);
        ret = ERROR_CRYPTO_DECRYPT_FAILED;
        goto finish;
    }
    *out_len = 0;
    rc = EVP_DecryptUpdate(ctx, out_buffer, &len, cipher_text, cipher_len);
    if (rc != OPSSL_OK) {
        printf(" * EVP_DecryptUpdate failed. line: %d\n", __LINE__);
        ret = ERROR_CRYPTO_DECRYPT_FAILED;
        goto finish;
    }
    *out_len += len;
    rc = EVP_DecryptFinal_ex(ctx, out_buffer + len, &len);
    if (rc != OPSSL_OK) {
        printf(" * EVP_DecryptFinal failed. line: %d\n", __LINE__);
        ret = ERROR_CRYPTO_DECRYPT_FAILED;
        goto finish;
    }
    *out_len += len;

    finish:
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);
    printf("OPENSSL DECRYPT FINISH. len = %d\n", *out_len);
    return ret;
}
