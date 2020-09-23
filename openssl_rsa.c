//
// Created by 魏昊晨 on 2020/9/5.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "openssl_rsa.h"

#define RSA_KEY_LENGTH 1024
static const char rnd_seed[] = "string to make the random number generator initialized";


int generate_rsa_key_files(const char *pub_keyfile, const char *pri_keyfile,
                           const unsigned char *passwd, int passwd_len)
{
    RSA *rsa = NULL;
    RAND_seed(rnd_seed, sizeof(rnd_seed));
    rsa = RSA_generate_key(RSA_KEY_LENGTH, RSA_F4, NULL, NULL);
    if(rsa == NULL) {
        printf("RSA_generate_key error!\n");
        return -1;
    }
    BIO *bp = BIO_new(BIO_s_file());
    if (NULL == bp) {
        printf("generate_key bio file new error!\n");
        return -1;
    }
    if(BIO_write_filename(bp, (void *)pub_keyfile) <= 0) {
        printf("BIO_write_filename error!\n");
        return -1;
    }
    if(PEM_write_bio_RSAPublicKey(bp, rsa) != 1) {
        printf("PEM_write_bio_RSAPublicKey error!\n");
        return -1;
    }
    printf("Create rsa public key ok!\n");
    BIO_free_all(bp);
    bp = BIO_new_file(pri_keyfile, "w+");
    if(NULL == bp){
        printf("generate_key bio file new error2!\n");
        return -1;
    }
    if(PEM_write_bio_RSAPrivateKey(bp, rsa,
                                   EVP_des_ede3_ofb(), (unsigned char *)passwd,
                                   passwd_len, NULL, NULL) != 1) {
        printf("PEM_write_bio_RSAPublicKey error!\n");
        return -1;
    }
    printf("Create rsa private key ok!\n");
    BIO_free_all(bp);
    RSA_free(rsa);

    return 0;
}
/*openssl rsa decrypt evp using*/
int openssl_evp_rsa_decrypt(unsigned char *cipher_text, size_t cipher_len,
                            unsigned char *plain_text, size_t *plain_len,
                            const unsigned char *pem_file, const unsigned char *passwd)
{
    int ret = 0;
    size_t out_len = 0;
    EVP_PKEY* private_evp_key = NULL;
    RSA *rsa = NULL;
    BIO *bp = NULL;
    FILE *fp = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    /*Check the user input.*/
    if (plain_text == NULL || *plain_len == 0 || cipher_text == NULL || cipher_len == 0) {
        printf("input parameters error, plain_text cipher_text or plain_len is NULL or 0.\n");
        ret = -1;
        goto finish;
    }
    if (NULL == pem_file) {
        printf("input pem_file name is invalid\n");
        ret = -1;
        goto finish;
    }
    fp = fopen((const char*)pem_file, "r");
    if (NULL == fp) {
        printf("input pem_file is not exit.\n");
        ret = -1;
        goto finish;
    }
    fclose(fp);
    fp = NULL;

    //OpenSSL_add_all_algorithms();
    bp = BIO_new(BIO_s_file());
    if (bp == NULL) {
        printf("BIO_new is failed.\n");
        ret = -1;
        goto finish;
    }
    /*read private key from pem file.*/
    ret = BIO_read_filename(bp, pem_file);
    rsa = PEM_read_bio_RSAPrivateKey(bp, &rsa, NULL, (void*)passwd);
    if (rsa == NULL) {
        ret = -1;
        printf("open_private_key failed to PEM_read_bio_RSAPrivateKey Failed, ret=%d\n", ret);
        goto finish;
    }
    private_evp_key = EVP_PKEY_new();
    if (private_evp_key == NULL) {
        ret = -1;
        printf("open_private_key EVP_PKEY_new failed\n");
        goto finish;
    }
    EVP_PKEY_assign_RSA(private_evp_key, rsa);
    /*do cipher.*/
    ctx = EVP_PKEY_CTX_new(private_evp_key, NULL);
    if (ctx == NULL) {
        ret = -1;
        printf("EVP_PKEY_CTX_new failed\n");
        goto finish;
    }
    ret = EVP_PKEY_decrypt_init(ctx);
    if (ret != 1) {
        printf("rsa_private_key decrypt failed to EVP_PKEY_decrypt_init. ret = %d\n", ret);
        goto finish;
    }
    ret = EVP_PKEY_CTX_set_rsa_padding(ctx, EVP_PADDING_PKCS7);
    if (ret != 1) {
        printf("EVP_PKEY_CTX_set_rsa_padding failed. ret = %d\n", ret);
        goto finish;
    }
    /* Determine buffer length */
    ret = EVP_PKEY_decrypt(ctx, NULL, &out_len, cipher_text, cipher_len);
    if (ret != 1) {
        printf("rsa_prikey_decrypt failed to EVP_PKEY_decrypt. ret = %d\n", ret);
        goto finish;
    }
    *plain_len = out_len;
    ret = EVP_PKEY_decrypt(ctx, plain_text, plain_len, cipher_text, cipher_len);
    if (ret != 1) {
        printf("rsa_prikey_decrypt failed to EVP_PKEY_decrypt. ret = %d\n", ret);
        goto finish;
    }
    ret = 0;
    finish:
    if (private_evp_key != NULL)
        EVP_PKEY_free(private_evp_key);
    if (bp != NULL)
        BIO_free(bp);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return ret;
}

/*openssl rsa cipher evp using*/
int openssl_evp_rsa_encrypt(	unsigned char *plain_text, size_t plain_len,
                                unsigned char *cipher_text, size_t *cipher_len,
                                unsigned char *pem_file)
{
    int ret = 0;
    RSA *rsa = NULL;
    EVP_PKEY* public_evp_key = NULL;
    FILE *fp = NULL;
    BIO *bp = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    /*Check the user input.*/
    if (plain_text == NULL || plain_len == 0 || cipher_text == NULL || *cipher_len == 0) {
        printf("input parameters error, plain_text cipher_text or plain_len is NULL or 0.\n");
        ret = -1;
        goto finish;
    }
    if (NULL == pem_file) {
        printf("input pem_file name is invalid\n");
        ret = -1;
        goto finish;
    }
    fp = fopen((const char*)pem_file, "r");
    if (NULL == fp) {
        printf("input pem_file is not exit.\n");
        ret = -1;
        goto finish;
    }
    fclose(fp);
    fp = NULL;

    //OpenSSL_add_all_algorithms();
    bp = BIO_new(BIO_s_file());
    if (bp == NULL) {
        printf("BIO_new is failed.\n");
        ret = -1;
        goto finish;
    }
    /*read public key from pem file.*/
    ret = BIO_read_filename(bp, pem_file);
    rsa = PEM_read_bio_RSAPublicKey(bp, NULL, NULL, NULL);
    if (rsa == NULL) {
        ret = -1;
        printf("open_public_key failed to PEM_read_bio_RSAPublicKey Failed, ret=%d\n", ret);
        goto finish;
    }
    public_evp_key = EVP_PKEY_new();
    if (public_evp_key == NULL) {
        ret = -1;
        printf("open_public_key EVP_PKEY_new failed\n");
        goto finish;
    }
    EVP_PKEY_assign_RSA(public_evp_key, rsa);

    /*do cipher.*/
    ctx = EVP_PKEY_CTX_new(public_evp_key, NULL);
    if (ctx == NULL) {
        ret = -1;
        printf("EVP_PKEY_CTX_new failed\n");
        goto finish;
    }
    ret = EVP_PKEY_encrypt_init(ctx);
    if (ret < 0) {
        printf("ras_pubkey_encrypt failed to EVP_PKEY_encrypt_init. ret = %d\n", ret);
        goto finish;
    }
    ret = EVP_PKEY_CTX_set_rsa_padding(ctx, EVP_PADDING_PKCS7);
    if (ret != 1) {
        printf("EVP_PKEY_CTX_set_rsa_padding failed. ret = %d\n", ret);
        goto finish;
    }
    ret = EVP_PKEY_encrypt(ctx, cipher_text, cipher_len, plain_text, plain_len);
    if (ret < 0) {
        printf("ras_pubkey_encrypt failed to EVP_PKEY_encrypt. ret = %d\n", ret);
        goto finish;
    }
    ret = 0;

    finish:
    if (public_evp_key != NULL)
        EVP_PKEY_free(public_evp_key);
    if (bp != NULL)
        BIO_free(bp);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

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
    RSA *rsa = NULL;
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
    rsa = PEM_read_bio_RSAPrivateKey(bp, &rsa, NULL, (void*)passwd);
    if (rsa == NULL) {
        ret = -1;
        printf("open_private_key failed to PEM_read_bio_RSAPrivateKey Failed, ret=%d\n", ret);
        goto finish;
    }
    private_evp_key = EVP_PKEY_new();
    if (private_evp_key == NULL) {
        ret = -1;
        printf("open_private_key EVP_PKEY_new failed\n");
        goto finish;
    }
    EVP_PKEY_assign_RSA(private_evp_key, rsa);
    /*do signature*/
    evp_md_ctx = EVP_MD_CTX_new();
    if (evp_md_ctx == NULL) {
        printf("EVP_MD_CTX_new failed.\n");
        ret = -1;
        goto finish;
    }
    EVP_MD_CTX_init(evp_md_ctx);
    ret = EVP_SignInit_ex(evp_md_ctx, EVP_md5(), NULL);
    if (ret != 1) {
        printf("EVP_SignInit_ex failed, ret = %d\n", ret);
        goto finish;
    }
    ret = EVP_SignUpdate(evp_md_ctx, sign_rom, sign_rom_len);
    if (ret != 1) {
        printf("EVP_SignUpdate failed, ret = %d\n", ret);
        goto finish;
    }
    ret = EVP_SignFinal(evp_md_ctx, result, (unsigned int*)result_len, private_evp_key);
    if (ret != 1) {
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
    RSA *rsa = NULL;
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
    ret = BIO_read_filename(bp, pub_pem_file);
    rsa = PEM_read_bio_RSAPublicKey(bp, NULL, NULL, NULL);
    if (rsa == NULL) {
        ret = -1;
        printf("open_public_key failed to PEM_read_bio_RSAPublicKey Failed, ret=%d\n", ret);
        goto finish;
    }
    public_evp_key = EVP_PKEY_new();
    if (public_evp_key == NULL) {
        ret = -1;
        goto finish;
    }
    EVP_PKEY_assign_RSA(public_evp_key, rsa);
    /*do verify*/
    evp_md_ctx = EVP_MD_CTX_new();
    if (evp_md_ctx == NULL) {
        printf("EVP_MD_CTX_new failed.\n");
        ret = -1;
        goto finish;
    }
    EVP_MD_CTX_init(evp_md_ctx);
    ret = EVP_VerifyInit_ex(evp_md_ctx, EVP_md5(), NULL);
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
