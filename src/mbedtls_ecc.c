//
// Created by carlos on 2020/11/12.
//

#include "mbedtls_ecc.h"

#define ECPARAMS    MBEDTLS_ECP_DP_SECP192R1

#if !defined(ECPARAMS)
#define ECPARAMS    mbedtls_ecp_curve_list()->grp_id
#endif

/* ECC encryt and decryt not supported by mbedtls */
int mbedtls_gen_ecc_key(const char *pub_keyfile, const char *pri_keyfile,
                        const unsigned char *passwd, int passwd_len)
{
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_type_t pk_alg = MBEDTLS_PK_ECKEY;
    int ret = ERROR_NONE, rc = MBEDTLS_EXIT_SUCCESS;
    unsigned char *pers = "gen ecc key!";
    /* curve id type :
     * https://tls.mbed.org/api/ecp_8h.html#af79e530ea8f8416480f805baa20b1a2d */
    mbedtls_ecp_group_id curve_id = MBEDTLS_ECP_DP_SECP192R1;
    unsigned char pem_buffer[16000];
    size_t buffer_len = 0;
    FILE *file = NULL;

    mbedtls_pk_init(&key);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    rc = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(pk_alg));
    if (rc != 0) {
        mbedtls_printf("mbedtls_pk_setup failed! rc = %d\n", rc);
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        goto finish;
    }

    rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                               &entropy,
                               (const unsigned char *) "ecdsa",
                               strlen(pers));
    if (rc != 0) {
        mbedtls_printf("mbedtls_ctr_drbg_seed failed! rc = %d\n", rc);
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        goto finish;
    }

    rc = mbedtls_ecp_gen_key(curve_id, mbedtls_pk_ec(key),
                             mbedtls_ctr_drbg_random,
                             &ctr_drbg);
    if (rc != 0) {
        mbedtls_printf("mbedtls_ecp_gen_key failed! rc = %d\n", rc);
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        goto finish;
    }

    /* saving the private key file */
    mbedtls_printf("[genkey]: Saving private key file.\n");
    rc = mbedtls_pk_write_key_pem(&key, pem_buffer, 16000);
    if (rc != 0) {
        mbedtls_printf("mbedtls_pk_write_key_pem failed! rc = %d\n", rc);
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        goto finish;
    }
    buffer_len = strlen((char*)pem_buffer);
    file = fopen(pri_keyfile, "w");
    if (file == NULL) {
        mbedtls_printf("failed! open pri pem file. \n");
        ret = -ERROR_COMMON_FILE_OPEN_FAILED;
        goto finish;
    }
    if (fwrite(pem_buffer, 1, buffer_len, file) != buffer_len) {
        mbedtls_printf("failed! write key pem word len.\n");
        ret = -ERROR_COMMON_FILE_WRITE_FAILED;
        goto finish;
    }
    fclose(file); file = NULL;

    /* saving the public key file */
    mbedtls_printf("[genkey]: Saving public key file.\n");
    memset(pem_buffer, 0, 16000);
    //ret = mbedtls_pk_parse_keyfile(&key, pri_keyfile, NULL);
    rc = mbedtls_pk_write_pubkey_pem(&key, pem_buffer, 16000);
    if (rc != 0) {
        mbedtls_printf("failed! mbedtls_pk_write_pubkey_pem return %d\n", ret);
        ret = -ERROR_CRYPTO_GEN_KEY_FAILED;
        goto finish;
    }
    buffer_len = strlen((char*)pem_buffer);
    file = fopen(pub_keyfile, "w");
    if (file == NULL) {
        mbedtls_printf("failed! write key pem file.\n");
        ret = -ERROR_COMMON_FILE_OPEN_FAILED;
        goto finish;
    }
    if (fwrite(pem_buffer, 1, buffer_len, file) != buffer_len) {
        mbedtls_printf("failed! write key pem file length failed!\n");
        ret = -ERROR_COMMON_FILE_WRITE_FAILED;
        goto finish;
    }
    fclose(file); file = NULL;
    ret = ERROR_NONE;
    mbedtls_printf("[genkey]: genkey finished.\n");

    finish:
    mbedtls_pk_free(&key);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    if (file != NULL) {
        fclose(file);
    }
    return ret;
}

int mbedtls_ecc_encrypt(unsigned char *plain_text, size_t plain_len,
                        unsigned char **cipher_text, size_t *cipher_len,
                        unsigned char *pem_file)
{
    int ret = ERROR_NONE, rc = MBEDTLS_EXIT_SUCCESS;
    FILE *fp = NULL;
    mbedtls_pk_context pk;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    const char *pers = "mbedtls_pk_encrypt";
    size_t enc_len = 0;
    /* 1. check input condition. */
    if (plain_text == NULL || plain_len == 0) {
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

    /* 2. using the mbedtls interface to encrypt msg. */
    /* note: For a 2048 bit RSA key, the maximum you can encrypt is 245 bytes (or 1960 bits). */
    /* 2.1 init random */
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                               &entropy, (const unsigned char *) pers,
                               strlen(pers));
    if (rc != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n",
                        (unsigned int) -rc );
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    /* 2.2 read the public key */
    mbedtls_pk_init(&pk);
    rc = mbedtls_pk_parse_public_keyfile(&pk, pem_file);
    if (rc != 0) {
        printf( " failed\n  ! mbedtls_pk_parse_public_keyfile returned -0x%04x\n",
                -rc );
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        goto finish;
    }
    fflush(stdout);
    /* 2.3 encrypt data */
    enc_len = mbedtls_pk_get_len(&pk);
    *cipher_text = malloc(enc_len);
    if (*cipher_text == NULL) {
        mbedtls_printf("malloc cipher text failed \n");
        ret = -ERROR_COMMON_MALLOC_FAILED;
        return ret;
        goto finish;
    }
    rc = mbedtls_pk_encrypt(&pk, plain_text, plain_len, \
                             *cipher_text, cipher_len, \
                             enc_len, \
                             mbedtls_ctr_drbg_random, \
                             &ctr_drbg);
    if (rc != 0) {
        printf( " failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n", -rc );
        ret = -ERROR_CRYPTO_DECRYPT_FAILED;
        goto finish;
    }
    /* 2.4 mv data to cipher text */
    ret = ERROR_NONE;

    finish:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    if (fp != NULL)
        fclose(fp);
    if (*cipher_text != NULL && ret != ERROR_NONE) {
        free(*cipher_text);
        *cipher_text = NULL;
    }
    return ret;
}

int mbedtls_ecc_decryt(unsigned char *cipher_text, size_t cipher_len,
                       unsigned char **plain_text, size_t *plain_len,
                       const unsigned char *pem_file, const unsigned char *passwd)
{
    int ret = ERROR_NONE, rc = MBEDTLS_EXIT_SUCCESS;
    FILE *fp = NULL;
    mbedtls_pk_context pk;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    const char *pers = "mbedtls_pk_encrypt";
    size_t dec_len = 0;
    /* 1. check input condition. */
    if (cipher_text == NULL || cipher_len == 0) {
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

    /* 2. using the mbedtls interface to encrypt msg. */
    /* note: For a 2048 bit RSA key, the maximum you can encrypt is 245 bytes (or 1960 bits). */
    /* 2.1 init random */
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                               &entropy, (const unsigned char *) pers,
                               strlen(pers));
    if (rc != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n",
                        (unsigned int) -rc );
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    /* 2.2 read the public key */
    mbedtls_pk_init(&pk);
    rc = mbedtls_pk_parse_public_keyfile(&pk, pem_file);
    if (rc != 0) {
        printf( " failed\n  ! mbedtls_pk_parse_public_keyfile returned -0x%04x\n",
                -rc );
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        goto finish;
    }
    fflush(stdout);
    /* 2.3 encrypt data */
    dec_len = mbedtls_pk_get_len(&pk);
    *plain_text = malloc(dec_len);
    if (*cipher_text == NULL) {
        mbedtls_printf("malloc cipher text failed \n");
        ret = -ERROR_COMMON_MALLOC_FAILED;
        return ret;
        goto finish;
    }
    rc = mbedtls_pk_decrypt(&pk, plain_text, plain_len, \
                             *plain_text, plain_len, \
                             dec_len, \
                             mbedtls_ctr_drbg_random, \
                             &ctr_drbg);
    if (rc != 0) {
        printf( " failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n", -rc );
        ret = -ERROR_CRYPTO_DECRYPT_FAILED;
        goto finish;
    }
    /* 2.4 mv data to cipher text */
    ret = ERROR_NONE;

    finish:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    if (fp != NULL)
        fclose(fp);
    if (*plain_text != NULL && ret != ERROR_NONE) {
        free(*plain_text);
        *plain_text = NULL;
    }
    return ret;
}

int mbedtls_ecdsa_signature(unsigned char *sign_rom, size_t sign_rom_len,
                            unsigned char *result, size_t *result_len,
                            const unsigned char *pem_file, const unsigned char *passwd)
{
    return mbedtls_rsa_pkcs8_signature(sign_rom, sign_rom_len, result, result_len, pem_file, passwd);
}

int mbedtls_ecdsa_verified(unsigned char *sign_rom, size_t sign_rom_len,
                           unsigned char *result, size_t result_len,
                           const unsigned char *pub_pem_file)
{
    return mbedtls_rsa_pkcs8_verified(sign_rom, sign_rom_len, result, result_len, pub_pem_file);
}
