//
// Created by carwei01 on 10/20/2020.
//

#include "openssl_ecc.h"

int generate_ecc_key_files(const char *pub_keyfile, const char *pri_keyfile,
                           const unsigned char *passwd, int passwd_len)
{
    int ret = 0;
    EC_KEY *ec_key = NULL;
    EC_GROUP *ec_group = NULL;
#ifdef MAKE_KEY_TO_RAM
    size_t prikey_len = 0;
	size_t pubkey_len = 0;
	unsigned char *prikey_buffer = NULL;
	unsigned char *pubkey_buffer = NULL;
#endif
    BIO *pri_bio = NULL;
    BIO *pub_bio = NULL;

    ec_key = EC_KEY_new();
    if (ec_key == NULL) {
        ret = -1;
        printf("EC_KEY_new() failed return NULL.\n");
        goto finish;
    }
    ec_group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (ec_group == NULL) {
        ret = -1;
        printf("EC_GROUP_new_by_curve_name() failed, return NULL.\n");
        goto finish;
    }
    ret = EC_KEY_set_group(ec_key, ec_group);
    if (ret != 1) {
        printf("EC_KEY_set_group() failed, ret = %d\n", ret);
        ret = -1;
        goto finish;
    }
    ret = EC_KEY_generate_key(ec_key);
    if (!ret) {
        printf("EC_KEY_generate_key() failed, ret = %d\n", ret);
        ret = -1;
        goto finish;
    }
    printf("Create sm2 private key ok!");
#ifdef MAKE_KEY_TO_RAM
    pri_bio = BIO_new(BIO_s_mem());
#else
    pri_bio = BIO_new(BIO_s_file());
#endif
    if (pri_bio == NULL) {
        ret = -1;
        printf("pri_bio = BIO_new(BIO_s_file()) failed, return NULL. \n");
        goto finish;
    }
    ret = BIO_write_filename(pri_bio, (void *)pri_keyfile);
    if (ret <= 0) {
        printf("BIO_write_filename error!\n");
        goto finish;
    }
    ret = PEM_write_bio_ECPrivateKey(pri_bio, ec_key, NULL, (unsigned char *)passwd, passwd_len, NULL, NULL);
    if (ret != 1) {
        printf("PEM_write_bio_ECPrivateKey error! ret = %d \n", ret);
        ret = -1;
        goto finish;
    }
#ifdef MAKE_KEY_TO_RAM
    pub_bio = BIO_new(BIO_s_mem());
#else
    pub_bio = BIO_new(BIO_s_file());
#endif
    if (pub_bio == NULL) {
        ret = -1;
        printf("pub_bio = BIO_new(BIO_s_file()) failed, return NULL. \n");
        goto finish;
    }
    ret = BIO_write_filename(pub_bio, (void *)pub_keyfile);
    if (ret <= 0) {
        printf("BIO_write_filename error!\n");
        goto finish;
    }
    ret = PEM_write_bio_EC_PUBKEY(pub_bio, ec_key);
    if (ret != 1) {
        ret = -1;
        printf("PEM_write_bio_EC_PUBKEY error!\n");
        goto finish;
    }
    printf("Create sm2 public key ok!");
#ifdef MAKE_KEY_TO_RAM
    PEM_write_bio_EC_PUBKEY(pub_bio, ec_key);
	prikey_len = BIO_pending(pri_bio);
	pubkey_len = BIO_Pending(pub_bio);
	prikey_buffer = (unsigned char*)OPENSSL_malloc((prikey_len + 1) * sizeof(unsigned char));
	if (prikey_buffer == NULL) {
		ret = -1;
		printf("prikey_buffer OPENSSL_malloc failed, return NULL. \n");
		goto finish;
	}
	pubkey_buffer = (unsigned char*)OPENSSL_malloc((pubkey_len + 1) * sizeof(unsigned char));
	if (pubkey_buffer == NULL) {
		ret = -1;
		printf("pubkey_buffer OPENSSL_malloc failed, return NULL. \n");
		goto finish;
	}
	BIO_read(pri_bio, prikey_buffer, prikey_len);
	BIO_read(pub_bio, pubkey_buffer, pubkey_len);
	prikey_buffer[prikey_len] = '\0';
	pubkey_buffer[pubkey_len] = '\0';
#endif
    finish:
    if (ec_key != NULL)
        EC_KEY_free(ec_key);
    if (ec_group != NULL)
        EC_GROUP_free(ec_group);
#ifdef MAKE_KEY_TO_RAM
    if (prikey_buffer != NULL)
		OPENSSL_free(prikey_buffer);
	if (pubkey_buffer != NULL)
		OPENSSL_free(pubkey_buffer);
#endif
    if (pub_bio != NULL)
        BIO_free_all(pub_bio);
    if (pri_bio != NULL)
        BIO_free_all(pri_bio);
    return ret;
}

/*openssl sm2 cipher evp using*/
int openssl_evp_ecc_encrypt(	unsigned char *plain_text, size_t plain_len,
                                unsigned char *cipher_text, size_t *cipher_len,
                                unsigned char *pem_file)
{
    int ret = 0;
    size_t out_len = 512;
    unsigned char cipper[512];
    FILE *fp = NULL;
    BIO *bp = NULL;
    EC_KEY *ec_key = NULL;
    EVP_PKEY* public_evp_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    /*Check the user input.*/
    if (plain_text == NULL || plain_len == 0 || cipher_text == NULL || *cipher_len == 0) {
        printf("input parameters error, plain_text cipher_text or plain_len is NULL or 0.\n");
        ret = -1;
        return ret;
    }
    if (NULL == pem_file) {
        printf("input pem_file name is invalid\n");
        ret = -1;
        return ret;
    }
    fp = fopen(pem_file, "r");
    if (NULL == fp) {
        printf("input pem_file is not exit.\n");
        ret = -1;
        return ret;
    }
    fclose(fp);
    fp = NULL;

    //OpenSSL_add_all_algorithms();
    bp = BIO_new(BIO_s_file());
    if (bp == NULL) {
        printf("BIO_new is failed.\n");
        ret = -1;
        return ret;
    }
    /*read public key from pem file.*/
    ret = BIO_read_filename(bp, pem_file);
    ec_key = PEM_read_bio_EC_PUBKEY(bp, NULL, NULL, NULL);
    if (ec_key == NULL) {
        ret = -1;
        printf("open_public_key failed to PEM_read_bio_EC_PUBKEY Failed, ret=%d\n", ret);
        goto finish;
    }
    public_evp_key = EVP_PKEY_new();
    if (public_evp_key == NULL) {
        ret = -1;
        printf("open_public_key EVP_PKEY_new failed\n");
        goto finish;
    }
    ret = EVP_PKEY_set1_EC_KEY(public_evp_key, ec_key);
    if (ret != 1) {
        ret = -1;
        printf("EVP_PKEY_set1_EC_KEY failed\n");
        goto finish;
    }
    ret = EVP_PKEY_set_alias_type(public_evp_key, EVP_PKEY_SM2);
    if (ret != 1) {
        printf("EVP_PKEY_set_alias_type to EVP_PKEY_SM2 failed! ret = %d\n", ret);
        ret = -1;
        goto finish;
    }
    /*modifying a EVP_PKEY to use a different set of algorithms than the default.*/

    /*do cipher.*/
    ctx = EVP_PKEY_CTX_new(public_evp_key, NULL);
    if (ctx == NULL) {
        ret = -1;
        printf("EVP_PKEY_CTX_new failed\n");
        goto finish;
    }
    ret = EVP_PKEY_encrypt_init(ctx);
    if (ret < 0) {
        printf("sm2_pubkey_encrypt failed to EVP_PKEY_encrypt_init. ret = %d\n", ret);
        EVP_PKEY_free(public_evp_key);
        EVP_PKEY_CTX_free(ctx);
        return ret;
    }
    ret = EVP_PKEY_encrypt(ctx, cipher_text, cipher_len, plain_text, plain_len);
    if (ret < 0) {
        printf("sm2_pubkey_encrypt failed to EVP_PKEY_encrypt. ret = %d\n", ret);
        EVP_PKEY_free(public_evp_key);
        EVP_PKEY_CTX_free(ctx);
        return ret;
    }
    ret = 0;
    finish:
    if (public_evp_key != NULL)
        EVP_PKEY_free(public_evp_key);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    if (bp != NULL)
        BIO_free(bp);
    if (ec_key != NULL)
        EC_KEY_free(ec_key);

    return ret;
}