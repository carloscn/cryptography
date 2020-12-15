//
// Created by 魏昊晨 on 2020/9/5.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "openssl_rsa.h"

static const char rnd_seed[] = "string to make the random number generator initialized";
/*
 * Gen RSA_F4 pkcs1 pem files.
 * */
int openssl_gen_rsa_pkcs1_pem_files(const char *pub_keyfile, const char *pri_keyfile,
                                    const unsigned char *passwd, int passwd_len, RSA_KEY_LEN rsa_key_len)
{
    int ret  = ERROR_NONE;
    /* openssl return 1 is ok! */
    int rc = OPSSL_OK;
    RSA *rsa = NULL;
    BIGNUM *bne = NULL;
    BIO *bp = NULL;
    int16_t key_size = 0;

    switch (rsa_key_len) {
        case RSA_LEN_1024:
            key_size = 1024;
            break;
        case RSA_LEN_2048:
            key_size = 2048;
            break;
        case RSA_LEN_4096:
            key_size = 4096;
            break;
        case RSA_LEN_8192:
            key_size = 8192;
            break;
        default:
            key_size = 0;
            break;
    }
    if (key_size == 0) {
        ret = -ERROR_CRYPTO_NO_ALGO;
        printf("no this rsa key size. %d", ret);
        goto finish;
    }
    /* RSA_F4 */
    rsa = RSA_new();
    if(rsa == NULL) {
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        printf("RSA new failed!\n");
        goto finish;
    }
    bne = BN_new();
    if (bne == NULL) {
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        printf("BN_new failed!\n");
        goto finish;
    }
    rc = BN_set_word(bne, RSA_F4);
    if (rc != OPSSL_OK) {
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        printf("BN set word failed! rc = %d\n", rc);
        goto finish;
    }
    rc = RSA_generate_key_ex(rsa, key_size, bne, NULL);
    if (rc != OPSSL_OK) {
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        printf("rsa gen key ex failed! rc = %d\n", rc);
        goto finish;
    }

    bp = BIO_new(BIO_s_file());
    if (bp == NULL) {
        ret = OPSSL_FAIL;
        printf("generate_key bio file new error!\n");
        goto finish;
    }
    rc = BIO_write_filename(bp, (void *)pub_keyfile);
    if( rc <= 0) {
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        printf("BIO_write_filename error, oprc = %d!\n", rc);
        goto finish;
    }
    rc = PEM_write_bio_RSAPublicKey(bp, rsa);
    if( rc != OPSSL_OK) {
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        printf("PEM_write_bio_RSAPublicKey error, oprc = %d!\n", rc);
        goto finish;
    }
    BIO_free_all(bp); bp = NULL;
    /* Gen the public key finished. */
    bp = BIO_new_file(pri_keyfile, "w+");
    if(NULL == bp){
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        printf("generate_key bio file new error!\n");
        goto finish;
    }
    rc = PEM_write_bio_RSAPrivateKey(bp, rsa, NULL,
                                    (unsigned char *)passwd,
                                    passwd_len, NULL, NULL);
    if (rc != OPSSL_OK) {
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        printf("PEM_write_bio_RSAPublicKey error! oprc = %d\n", rc);
        goto finish;
    }
    printf("Generate key pair PKCS#1 format successfully.\n");
    printf("->private key: %s\n", pri_keyfile);
    printf("->public key: %s\n\n", pub_keyfile);
    ret = 0;
    finish:
    if (bp != NULL)
        BIO_free_all(bp);
    if (rsa != NULL)
        RSA_free(rsa);
    if (bne != NULL)
        BN_free(bne);
    return ret;
}
/*
 * Gen key pkcs#8 format.
 * */
int openssl_gen_rsa_pkcs8_pem_files(const char *pub_keyfile, const char *pri_keyfile,
                                    const unsigned char *passwd, int passwd_len, RSA_KEY_LEN rsa_key_len)
{
    int ret = ERROR_NONE;
    int rc = OPSSL_OK;
    RSA *rsa = NULL;
    BIGNUM *bne = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *bp = NULL;
    int16_t key_size = 0;

    switch (rsa_key_len) {
        case RSA_LEN_1024:
            key_size = 1024;
            break;
        case RSA_LEN_2048:
            key_size = 2048;
            break;
        case RSA_LEN_4096:
            key_size = 4096;
            break;
        case RSA_LEN_8192:
            key_size = 8192;
            break;
        default:
            key_size = 0;
            break;
    }
    if (key_size == 0) {
        ret = -ERROR_CRYPTO_NO_ALGO;
        printf("no this rsa key size. %d", ret);
        goto finish;
    }
    rsa = RSA_new();
    if(rsa == NULL) {
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        printf("RSA new failed!\n");
        goto finish;
    }
    bne = BN_new();
    if (bne == NULL) {
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        printf("BN_new failed!\n");
        goto finish;
    }
    rc = BN_set_word(bne, RSA_F4);
    if (rc != OPSSL_OK) {
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        printf("BN set word failed! rc = %d\n", rc);
        goto finish;
    }
    rc = RSA_generate_key_ex(rsa, key_size, bne, NULL);
    if (rc != OPSSL_OK) {
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        printf("rsa gen key ex failed! rc = %d\n", rc);
        goto finish;
    }
    bp = BIO_new(BIO_s_file());
    if (NULL == bp) {
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        printf("generate_key bio file new error!\n");
        goto finish;
    }
    rc = BIO_write_filename(bp, (void *)pub_keyfile);
    if( rc <= 0) {
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        printf("BIO_write_filename error! return %d\n", rc);
        goto finish;
    }
    /* gen the PKCS#8 format pem. */
    rc = PEM_write_bio_RSA_PUBKEY(bp, rsa);
    if( rc != OPSSL_OK) {
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        printf("PEM_write_bio_RSAPublicKey error! return %d\n", rc);
        goto finish;
    }
    BIO_free_all(bp); bp = NULL;
    /* generate public finish. */
    bp = BIO_new_file(pri_keyfile, "w+");
    if(bp == NULL){
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        printf("generate_key bio file new error!\n");
        goto finish;
    }
    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        printf("EVP_PKEY_new failed\n");
        goto finish;
    }
    rc = EVP_PKEY_assign_RSA(pkey, rsa);
    if (rc != OPSSL_OK) {
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        printf("EVP_PKEY_assign_RSA failed! return %d\n", rc);
        goto finish;
    }
    rc = PEM_write_bio_PKCS8PrivateKey(bp, pkey,
                                       NULL, (unsigned char *)passwd,
                                       passwd_len, NULL, NULL);
    if(rc != OPSSL_OK) {
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        printf("PEM_write_bio_RSAPublicKey error! return %d\n", rc);
        goto finish;
    }
    ret = ERROR_NONE;
    printf("generate PKCS#8 RSA key finish!\n");
    printf("->private key: %s\n", pri_keyfile);
    printf("->public key: %s\n\n", pub_keyfile);
    finish:
    /* can not free rsa and bne.*/
    // if (rsa != NULL)
    //    RSA_free(rsa);
    // if (bne != NULL)
    //    BN_free(bne);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (bp != NULL)
        BIO_free_all(bp);
    return ret;
}

int openssl_evp_pkcs1_rsa_encrypt(unsigned char *plain_text, size_t plain_len,
                                  unsigned char **cipher_text, size_t *cipher_len,
                                  unsigned char *pem_file)
{
    int ret = ERROR_NONE;
    int rc = OPSSL_OK;
#ifndef PKCS8
    RSA *rsa = NULL;
#endif
    EVP_PKEY* public_evp_key = NULL;
    FILE *fp = NULL;
    BIO *bp = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t algo_len = 0;
    size_t bulk_len = 0;
    size_t enco_len = 0;
    size_t cipe_len = 0;
    size_t temp_len = 0;
    size_t rest_len = 0;
    unsigned char * msg_hook = NULL;
    uint16_t i = 0;
    /*Check the user input.*/
    if (plain_text == NULL || plain_len == 0 || *cipher_len == 0) {
        printf("input parameters error, plain_text cipher_text or plain_len is NULL or 0.\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    if (NULL == pem_file) {
        printf("input pem_file name is invalid\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    fp = fopen((const char*)pem_file, "r");
    if (NULL == fp) {
        printf("input pem_file is not exit.\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    fclose(fp);
    fp = NULL;
    OpenSSL_add_all_algorithms();
    public_evp_key = EVP_PKEY_new();
    if (public_evp_key == NULL) {
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        printf("open_public_key EVP_PKEY_new failed\n");
        goto finish;
    }
    bp = BIO_new(BIO_s_file());
    if (bp == NULL) {
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        printf("BIO new failed.\n");
        goto finish;
    }
    rc = BIO_read_filename(bp, pem_file);
    if (rc != OPSSL_OK) {
        rc = -ERROR_CRYPTO_READ_KEY_FAILED;
        printf("BIO_read_filename %s failed,  rc = %d\n", pem_file, rc);
        goto finish;
    }
    rsa = PEM_read_bio_RSAPublicKey(bp, &rsa, NULL, NULL);
    if (rsa == NULL) {
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        printf("open RSAPublicKey failed.\n");
        goto finish;
    }
    EVP_PKEY_assign_RSA(public_evp_key, rsa);
    algo_len = RSA_size(rsa);
    bulk_len = algo_len - RSA_PKCS1_PADDING_SIZE;
    cipe_len = algo_len * (plain_len/bulk_len + ((plain_len%bulk_len)?1:0));
    printf("cipher msg need space size : %ld\n", cipe_len);
    *cipher_text = (unsigned char *)malloc(cipe_len);
    if (cipher_text == NULL) {
        printf("cipher_text malloc failed\n");
        ret = -ERROR_COMMON_MALLOC_FAILED;
        goto finish;
    }
    /*do cipher.*/
    ctx = EVP_PKEY_CTX_new(public_evp_key, NULL);
    if (ctx == NULL) {
        ret = -ERROR_CRYPTO_ENCRYPT_FAILED;
        printf("EVP_PKEY_CTX_new failed\n");
        goto finish;
    }
    ret = EVP_PKEY_encrypt_init(ctx);
    if (ret < 0) {
        printf("ras_pubkey_encrypt failed to EVP_PKEY_encrypt_init. ret = %d\n", ret);
        goto finish;
    }
    msg_hook = plain_text;
    rest_len = plain_len;
    for (i = 0; rest_len > 0; i ++) {
       if (rest_len < bulk_len)
           bulk_len = rest_len;
       printf("enc bulk_num %d, bulk_len %ld\n", i, bulk_len);
       rc = EVP_PKEY_encrypt(ctx, NULL, &temp_len, msg_hook, bulk_len);
       if (rc < 0) {
           ret = -ERROR_CRYPTO_ENCRYPT_FAILED;
           printf("first rsa_pubkey_encrypt failed to EVP_PKEY_encrypt. rc = %d\n", rc);
           goto finish;
       }
       if (temp_len < sizeof(*cipher_text)) {
           ret = -ERROR_COMMON_BUFFER_INSUFFIENT;
           printf("cipher text is too long, buffer space is insuffient.\n");
           goto finish;
       }
       rc = EVP_PKEY_encrypt(ctx, (unsigned char*)(*cipher_text + i*algo_len),
                             &temp_len, msg_hook, bulk_len);
       if (rc < 0) {
           ret = -ERROR_CRYPTO_ENCRYPT_FAILED;
           printf("second rsa_pubkey_encrypt failed to EVP_PKEY_encrypt. rc = %d\n", rc);
           goto finish;
       }
       msg_hook += bulk_len;
       enco_len += temp_len;
       rest_len -= bulk_len;
    }
    if (enco_len != cipe_len) {
        ret = -ERROR_CRYPTO_ENCRYPT_FAILED;
        printf("rsa enc len error, calc_len = %ld, cipe_len = %ld\n",
               enco_len, cipe_len);
        goto finish;
    }
    *cipher_len = enco_len;
    ret = ERROR_NONE;

    finish:
    if (public_evp_key != NULL)
        EVP_PKEY_free(public_evp_key);
    if (bp != NULL)
        BIO_free(bp);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    if (*cipher_text != NULL && ret != ERROR_NONE)
        free(*cipher_text);
    return ret;
}
/*openssl rsa decrypt evp using*/
int openssl_evp_pkcs1_rsa_decrypt(unsigned char *cipher_text, size_t cipher_len,
                                  unsigned char **plain_text, size_t *plain_len,
                                  const unsigned char *pem_file, const unsigned char *passwd)
{
    int rc = OPSSL_OK;
    int ret = ERROR_NONE;
    uint16_t i = 0;
    size_t out_len = 0;
    EVP_PKEY* private_evp_key = NULL;
#ifndef PKCS8
    RSA *rsa = NULL;
#endif
    BIO *bp = NULL;
    FILE *fp = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t algo_len = 0;
    size_t dec_times = 0;
    size_t deco_len = 0;

    /*Check the user input.*/
    if (*plain_len == 0 || cipher_text == NULL || cipher_len == 0) {
        printf("input parameters error, plain_text cipher_text or plain_len is NULL or 0.\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    if (NULL == pem_file) {
        printf("input pem_file name is invalid\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    fp = fopen((const char*)pem_file, "r");
    if (NULL == fp) {
        printf("input pem_file is not exit.\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    fclose(fp);
    fp = NULL;

    OpenSSL_add_all_algorithms();
    bp = BIO_new(BIO_s_file());
    if (bp == NULL) {
        printf("BIO_new is failed.\n");
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        goto finish;
    }
    /*read private key from pem file.*/
    rc = BIO_read_filename(bp, pem_file);
    if (rc != OPSSL_OK) {
        printf("BIO_read_filename failed.\n");
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        goto finish;
    }
    private_evp_key = EVP_PKEY_new();
    if (private_evp_key == NULL) {
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        printf("open_private_key EVP_PKEY_new failed\n");
        goto finish;
    }
    rsa = PEM_read_bio_RSAPrivateKey(bp, &rsa, NULL, (void*)passwd);
    if (rsa == NULL) {
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        printf("open_private_key failed to PEM_read_bio_RSAPrivateKey Failed, ret=%d\n", ret);
        goto finish;
    }
    EVP_PKEY_assign_RSA(private_evp_key, rsa);
    /*do cipher.*/
    ctx = EVP_PKEY_CTX_new(private_evp_key, NULL);
    if (ctx == NULL) {
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        printf("EVP_PKEY_CTX_new failed\n");
        goto finish;
    }
    rc = EVP_PKEY_decrypt_init(ctx);
    if (rc != OPSSL_OK) {
        ret = -ERROR_CRYPTO_DECRYPT_FAILED;
        printf("rsa_private_key decrypt failed to EVP_PKEY_decrypt_init. ret = %d\n", ret);
        goto finish;
    }
    /* get algo len */
    algo_len = RSA_size(rsa);
    dec_times = cipher_len / algo_len;
    *plain_text = (unsigned char *)malloc(dec_times * algo_len);
    for (i = 0; i < dec_times; i ++) {
        printf("decrypt bulk %d \n", i);
        /* Determine buffer length */
        rc = EVP_PKEY_decrypt(ctx, NULL,
                               &out_len,
                               (unsigned char *)(cipher_text + i*algo_len),
                               algo_len);
        if (rc != OPSSL_OK) {
            printf("1st rsa_prikey_decrypt failed to EVP_PKEY_decrypt. rc = %d\n", rc);
            ret = -ERROR_CRYPTO_DECRYPT_FAILED;
            goto finish;
        }
        deco_len += out_len - RSA_PKCS1_PADDING_SIZE;
        if (deco_len + RSA_PKCS1_PADDING_SIZE > dec_times * algo_len) {
            printf("decryption buffer space is insuffient, deco_len %ld buffer len %ld\n",
                   deco_len, dec_times * algo_len);
            ret = -ERROR_COMMON_BUFFER_INSUFFIENT;
            goto finish;
        }
        rc = EVP_PKEY_decrypt(ctx, (unsigned char *)(*plain_text + deco_len - (out_len - RSA_PKCS1_PADDING_SIZE)),
                               &out_len,
                               (unsigned char *)(cipher_text + i*algo_len),
                               algo_len);
        if (rc != OPSSL_OK) {
            printf("2st rsa_prikey_decrypt failed to EVP_PKEY_decrypt. rc = %d\n", rc);
            ret = -ERROR_CRYPTO_DECRYPT_FAILED;
            goto finish;
        }
    }
    *plain_len = deco_len;
    ret = ERROR_NONE;
    finish:
    if (private_evp_key != NULL)
        EVP_PKEY_free(private_evp_key);
    if (bp != NULL)
        BIO_free(bp);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    if (*plain_text != NULL && ret != ERROR_NONE)
        free(*plain_text);

    return ret;
}

int openssl_evp_pkcs8_rsa_encrypt(unsigned char *plain_text, size_t plain_len,
                                  unsigned char **cipher_text, size_t *cipher_len,
                                  unsigned char *pem_file)
{
    int ret = ERROR_NONE;
    int rc = OPSSL_OK;
    EVP_PKEY* public_evp_key = NULL;
    FILE *fp = NULL;
    BIO *bp = NULL;
    RSA *rsa = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t algo_len = 0;
    size_t bulk_len = 0;
    size_t enco_len = 0;
    size_t cipe_len = 0;
    size_t temp_len = 0;
    size_t rest_len = 0;
    unsigned char * msg_hook = NULL;
    uint16_t i = 0;
    /*Check the user input.*/
    if (plain_text == NULL || plain_len == 0 || *cipher_len == 0) {
        printf("input parameters error, plain_text cipher_text or plain_len is NULL or 0.\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    if (NULL == pem_file) {
        printf("input pem_file name is invalid\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    fp = fopen((const char*)pem_file, "r");
    if (NULL == fp) {
        printf("input pem_file is not exit.\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    fclose(fp);
    fp = NULL;
    OpenSSL_add_all_algorithms();
    public_evp_key = EVP_PKEY_new();
    if (public_evp_key == NULL) {
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        printf("open_public_key EVP_PKEY_new failed\n");
        goto finish;
    }
    bp = BIO_new(BIO_s_file());
    if (bp == NULL) {
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        printf("BIO new failed.\n");
        goto finish;
    }
    rc = BIO_read_filename(bp, pem_file);
    if (rc != OPSSL_OK) {
        rc = -ERROR_CRYPTO_READ_KEY_FAILED;
        printf("BIO_read_filename %s failed,  rc = %d\n", pem_file, rc);
        goto finish;
    }
    public_evp_key = PEM_read_bio_PUBKEY(bp, &public_evp_key, NULL, NULL);
    if (public_evp_key == NULL) {
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        printf("open_public_key %s failed to PEM_read_bio_RSAPublicKey Failed, ret=%d\n", pem_file, ret);
        goto finish;
    }
    rsa = EVP_PKEY_get0_RSA(public_evp_key);
    if (rsa == NULL) {
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        printf("get rsa evpkey -> rsa failed\n");
        goto finish;
    }
    algo_len = RSA_size(rsa);
    bulk_len = algo_len - RSA_PKCS1_PADDING_SIZE;
    cipe_len = algo_len * (plain_len/bulk_len + ((plain_len%bulk_len)?1:0));
    printf("cipher msg need space size : %ld\n", cipe_len);
    *cipher_text = (unsigned char *)malloc(cipe_len);
    if (cipher_text == NULL) {
        printf("cipher_text malloc failed\n");
        ret = -ERROR_COMMON_MALLOC_FAILED;
        goto finish;
    }
    /*do cipher.*/
    ctx = EVP_PKEY_CTX_new(public_evp_key, NULL);
    if (ctx == NULL) {
        ret = -ERROR_CRYPTO_ENCRYPT_FAILED;
        printf("EVP_PKEY_CTX_new failed\n");
        goto finish;
    }
    ret = EVP_PKEY_encrypt_init(ctx);
    if (ret < 0) {
        printf("ras_pubkey_encrypt failed to EVP_PKEY_encrypt_init. ret = %d\n", ret);
        goto finish;
    }
    msg_hook = plain_text;
    rest_len = plain_len;
    for (i = 0; rest_len > 0; i ++) {
        if (rest_len < bulk_len)
            bulk_len = rest_len;
        printf("enc bulk_num %ld, bulk_len %ld\n", i, bulk_len);
        rc = EVP_PKEY_encrypt(ctx, NULL, &temp_len, msg_hook, bulk_len);
        if (rc < 0) {
            ret = -ERROR_CRYPTO_ENCRYPT_FAILED;
            printf("first rsa_pubkey_encrypt failed to EVP_PKEY_encrypt. rc = %d\n", rc);
            goto finish;
        }
        if (temp_len < sizeof(*cipher_text)) {
            ret = -ERROR_COMMON_BUFFER_INSUFFIENT;
            printf("cipher text is too long, buffer space is insuffient.\n");
            goto finish;
        }
        rc = EVP_PKEY_encrypt(ctx, (unsigned char*)(*cipher_text + i*algo_len),
                              &temp_len, msg_hook, bulk_len);
        if (rc < 0) {
            ret = -ERROR_CRYPTO_ENCRYPT_FAILED;
            printf("second rsa_pubkey_encrypt failed to EVP_PKEY_encrypt. rc = %d\n", rc);
            goto finish;
        }
        msg_hook += bulk_len;
        enco_len += temp_len;
        rest_len -= bulk_len;
    }
    if (enco_len != cipe_len) {
        ret = -ERROR_CRYPTO_ENCRYPT_FAILED;
        printf("rsa enc len error, calc_len = %ld, cipe_len = %ld\n",
               enco_len, cipe_len);
        goto finish;
    }
    *cipher_len = enco_len;
    ret = ERROR_NONE;

    finish:
    if (public_evp_key != NULL)
        EVP_PKEY_free(public_evp_key);
    if (bp != NULL)
        BIO_free(bp);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    if (*cipher_text != NULL && ret != ERROR_NONE)
        free(*cipher_text);
    return ret;
}
/*openssl rsa decrypt evp using*/
int openssl_evp_pkcs8_rsa_decrypt(unsigned char *cipher_text, size_t cipher_len,
                                  unsigned char **plain_text, size_t *plain_len,
                                  const unsigned char *pem_file, const unsigned char *passwd)
{
    int rc = OPSSL_OK;
    int ret = ERROR_NONE;
    uint16_t i = 0;
    size_t out_len = 0;
    EVP_PKEY* private_evp_key = NULL;
    RSA *rsa = NULL;
    BIO *bp = NULL;
    FILE *fp = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t algo_len = 0;
    size_t dec_times = 0;
    size_t deco_len = 0;

    /*Check the user input.*/
    if (*plain_len == 0 || cipher_text == NULL || cipher_len == 0) {
        printf("input parameters error, plain_text cipher_text or plain_len is NULL or 0.\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    if (NULL == pem_file) {
        printf("input pem_file name is invalid\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    fp = fopen((const char*)pem_file, "r");
    if (NULL == fp) {
        printf("input pem_file is not exit.\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    fclose(fp);
    fp = NULL;

    OpenSSL_add_all_algorithms();
    bp = BIO_new(BIO_s_file());
    if (bp == NULL) {
        printf("BIO_new is failed.\n");
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        goto finish;
    }
    /*read private key from pem file.*/
    rc = BIO_read_filename(bp, pem_file);
    if (rc != OPSSL_OK) {
        printf("BIO_read_filename failed.\n");
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        goto finish;
    }
    private_evp_key = EVP_PKEY_new();
    if (private_evp_key == NULL) {
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        printf("open_private_key EVP_PKEY_new failed\n");
        goto finish;
    }
    private_evp_key = PEM_read_bio_PrivateKey(bp, private_evp_key, (void*)passwd, NULL);
    if (private_evp_key == NULL) {
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        printf("PEM read bio PrivateKey faield\n");
        goto finish;
    }
    /*do cipher.*/
    ctx = EVP_PKEY_CTX_new(private_evp_key, NULL);
    if (ctx == NULL) {
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        printf("EVP_PKEY_CTX_new failed\n");
        goto finish;
    }
    rc = EVP_PKEY_decrypt_init(ctx);
    if (rc != OPSSL_OK) {
        ret = -ERROR_CRYPTO_DECRYPT_FAILED;
        printf("rsa_private_key decrypt failed to EVP_PKEY_decrypt_init. ret = %d\n", ret);
        goto finish;
    }
    rsa = EVP_PKEY_get0_RSA(private_evp_key);
    if (rsa == NULL) {
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        printf("evpkey -> rsa handler failed \n");
        goto finish;
    }
    /* get algo len */
    algo_len = RSA_size(rsa);
    dec_times = cipher_len / algo_len;
    *plain_text = (unsigned char *)malloc(dec_times * algo_len);
    for (i = 0; i < dec_times; i ++) {
        printf("decrypt bulk %d \n", i);
        /* Determine buffer length */
        rc = EVP_PKEY_decrypt(ctx, NULL,
                              &out_len,
                              (unsigned char *)(cipher_text + i*algo_len),
                              algo_len);
        if (rc != OPSSL_OK) {
            printf("1st rsa_prikey_decrypt failed to EVP_PKEY_decrypt. rc = %d\n", rc);
            ret = -ERROR_CRYPTO_DECRYPT_FAILED;
            goto finish;
        }
        deco_len += out_len - RSA_PKCS1_PADDING_SIZE;
        if (deco_len + RSA_PKCS1_PADDING_SIZE > dec_times * algo_len) {
            printf("decryption buffer space is insuffient, deco_len %ld buffer len %ld\n",
                   deco_len, dec_times * algo_len);
            ret = -ERROR_COMMON_BUFFER_INSUFFIENT;
            goto finish;
        }
        rc = EVP_PKEY_decrypt(ctx, (unsigned char *)(*plain_text + deco_len - (out_len - RSA_PKCS1_PADDING_SIZE)),
                              &out_len,
                              (unsigned char *)(cipher_text + i*algo_len),
                              algo_len);
        if (rc != OPSSL_OK) {
            printf("2st rsa_prikey_decrypt failed to EVP_PKEY_decrypt. rc = %d\n", rc);
            ret = -ERROR_CRYPTO_DECRYPT_FAILED;
            goto finish;
        }
    }
    *plain_len = deco_len;
    ret = ERROR_NONE;
    finish:
    if (private_evp_key != NULL)
        EVP_PKEY_free(private_evp_key);
    if (bp != NULL)
        BIO_free(bp);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    if (*plain_text != NULL && ret != ERROR_NONE)
        free(*plain_text);

    return ret;
}

// RSA_PKCS1_PADDING  RSA_OAEP_PADDING
int openssl_evp_rsa_signature(unsigned char *sign_rom, size_t sign_rom_len,
                              unsigned char *result, size_t *result_len,
                              const unsigned char *priv_pem_file, const unsigned char *passwd)
{
    int ret = 0;
    FILE *fp = NULL;
    EVP_PKEY* private_evp_key = NULL;
#ifndef PKC8
    RSA *rsa = NULL;
#endif
    BIO *bp = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD_CTX *evp_md_ctx = NULL;

    /*Check the user input.*/
    if (sign_rom == NULL || sign_rom_len == 0 || result == NULL || *result_len == 0) {
        printf("input parameters error, content or len is NULL or 0.\n");
        ret = -1;
        goto finish;
    }
    if (NULL == priv_pem_file) {
        printf("input pem_file name is invalid\n");
        ret = -1;
        return ret;
    }
    fp = fopen((const char*)priv_pem_file, "r");
    if (NULL == fp) {
        printf("input pem_file is not exit.\n");
        ret = -1;
        goto finish;
    }
    fclose(fp);
    fp = NULL;
    /*read private key from pem file to private_evp_key*/
    //OpenSSL_add_all_algorithms();
    bp = BIO_new(BIO_s_file());
    if (bp == NULL) {
        printf("BIO_new is failed.\n");
        ret = -1;
        goto finish;
    }
    ret = BIO_read_filename(bp, priv_pem_file);
    if (ret != OPSSL_OK) {
        ret = -1;
        goto finish;
    }
    private_evp_key = EVP_PKEY_new();
    if (private_evp_key == NULL) {
        ret = -1;
        printf("open_private_key EVP_PKEY_new failed\n");
        goto finish;
    }
#ifdef PKCS8
    private_evp_key = PEM_read_bio_PrivateKey(bp, private_evp_key, (void*)passwd, NULL);
    if (private_evp_key == NULL) {
        ret = -1;
        printf("open_private_key EVP_PKEY_new failed\n");
        goto finish;
    }
#else
    rsa = PEM_read_bio_RSAPrivateKey(bp, &rsa, (void*)passwd, NULL);
    if (rsa == NULL) {
        ret = -1;
        printf("open_private_key failed to PEM_read_bio_RSAPrivateKey Failed, ret=%d\n", ret);
        goto finish;
    }
   EVP_PKEY_assign_RSA(private_evp_key, rsa);
#endif
    /*do signature*/
    evp_md_ctx = EVP_MD_CTX_new();
    if (evp_md_ctx == NULL) {
        printf("EVP_MD_CTX_new failed.\n");
        ret = -1;
        goto finish;
    }
    EVP_MD_CTX_init(evp_md_ctx);
    ret = EVP_SignInit_ex(evp_md_ctx, EVP_sha256(), NULL);
    if (ret != 1) {
        ret = -1;
        printf("EVP_SignInit_ex failed, ret = %d\n", ret);
        goto finish;
    }
    ret = EVP_SignUpdate(evp_md_ctx, sign_rom, sign_rom_len);
    if (ret != 1) {
        ret = -1;
        printf("EVP_SignUpdate failed, ret = %d\n", ret);
        goto finish;
    }
    ret = EVP_SignFinal(evp_md_ctx, result, (unsigned int*)result_len, private_evp_key);
    if (ret != 1) {
        ret = -1;
        printf("EVP_SignFinal failed, ret = %d\n", ret);
        goto finish;
    }
    ret = 0;
    finish:
    if (private_evp_key != NULL)
        EVP_PKEY_free(private_evp_key);
    if (bp != NULL)
        BIO_free(bp);
    if (evp_md_ctx != NULL)
        EVP_MD_CTX_free(evp_md_ctx);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    return ret;
}

int openssl_evp_rsa_verify(unsigned char *sign_rom, size_t sign_rom_len,
                           unsigned char *result, size_t result_len,
                           const unsigned char *pub_pem_file)
{
    int ret = 0;
    FILE *fp = NULL;
    EVP_PKEY* public_evp_key = NULL;
#ifndef PKCS8
    RSA *rsa = NULL;
#endif
    BIO *bp = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD_CTX *evp_md_ctx = NULL;

    /*Check the user input.*/
    if (sign_rom == NULL || sign_rom_len == 0 || result == NULL || result_len == 0) {
        printf("input parameters error, content or len is NULL or 0.\n");
        ret = -1;
        goto finish;
    }
    if (NULL == pub_pem_file) {
        printf("input pem_file name is invalid\n");
        ret = -1;
        goto finish;
    }
    fp = fopen((const char*)pub_pem_file, "r");
    if (NULL == fp) {
        printf("input pem_file is not exit.\n ");
        ret = -1;
        goto finish;
    }
    fclose(fp);
    fp = NULL;
    /*read public key from pem file to private_evp_key*/
    //OpenSSL_add_all_algorithms();
    bp = BIO_new(BIO_s_file());
    if (bp == NULL) {
        printf("BIO_new is failed.\n");
        ret = -1;
        goto finish;
    }
    public_evp_key = EVP_PKEY_new();
    ret = BIO_read_filename(bp, pub_pem_file);
    if (ret != OPSSL_OK) {
        ret = -1;
        goto finish;
    }
#ifdef PKCS8
    public_evp_key = PEM_read_bio_PUBKEY(bp, &public_evp_key, NULL, NULL);
    if (public_evp_key == NULL) {
        ret = -1;
        printf("open_public_key %s failed to PEM_read_bio_RSAPublicKey Failed, ret=%d\n", pub_pem_file, ret);
        goto finish;
    }
#else
    rsa = PEM_read_bio_RSAPublicKey(bp, NULL, NULL, NULL);
    if (rsa == NULL) {
        ret = -1;
        printf("open_public_key failed to PEM_read_bio_RSAPublicKey Failed, ret=%d\n", ret);
        goto finish;
    }
    EVP_PKEY_assign_RSA(public_evp_key, rsa);
#endif
    /*do verify*/
    evp_md_ctx = EVP_MD_CTX_new();
    if (evp_md_ctx == NULL) {
        printf("EVP_MD_CTX_new failed.\n");
        ret = -1;
        goto finish;
    }
    EVP_MD_CTX_init(evp_md_ctx);
    ret = EVP_VerifyInit_ex(evp_md_ctx, EVP_sha512(), NULL);
    if (ret != 1) {
        printf("EVP_VerifyInit_ex failed, ret = %d\n", ret);
        goto finish;
    }
    ret = EVP_VerifyUpdate(evp_md_ctx, result, result_len);
    if (ret != 1) {
        printf("EVP_VerifyUpdate failed, ret = %d\n", ret);
        goto finish;
    }
    ret = EVP_VerifyFinal(evp_md_ctx, sign_rom, (unsigned int)sign_rom_len, public_evp_key);
    if (ret != 1) {
        printf("EVP_VerifyFinal failed, ret = %d\n", ret);
        goto finish;
    }
    ret = 0;
    finish:
    if (public_evp_key != NULL)
        EVP_PKEY_free(public_evp_key);
    if (bp != NULL)
        BIO_free(bp);
    if (evp_md_ctx != NULL)
        EVP_MD_CTX_free(evp_md_ctx);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return ret;
}