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

int mbedtls_ecc_encrypt(const unsigned char *plain_text, size_t plain_len,
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

int mbedtls_ecc_decryt(const unsigned char *cipher_text, size_t cipher_len,
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

int mbedtls_pk_ecc_signature(const unsigned char *sign_rom, size_t sign_rom_len,
                             unsigned char *result, size_t *result_len,
                             SCHEME_TYPE sch,
                             const unsigned char *pem_file, const unsigned char *passwd)
{
    int ret = ERROR_NONE;
    int rc = MBEDTLS_EXIT_SUCCESS;
    FILE *fp = NULL;
    mbedtls_pk_context pk;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    /*MD MAX LEN is 64*/
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    /*SIGN RESULT MAX LEN is 1024*/
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    const char *pers = "mbedtls_ecc_signature";
    size_t outlen = 0;
    size_t hash_len = 0;

    /* 1. check input condition. */
    if (sign_rom == NULL || result == NULL || sign_rom_len == 0) {
        printf("input parameters error, input is NULL or 0.\n");
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
    /* 2. using the mbedtls interface to sign msg. */
    /* 2.1 init random */
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    rc = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                 &entropy, (const unsigned char *) pers,
                                 strlen(pers));
    if (rc != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n",
                        (unsigned int) -rc );
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    /* 2.2 read the private key */
    mbedtls_pk_init(&pk);
    rc = mbedtls_pk_parse_keyfile(&pk, pem_file, passwd);
    if (rc != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_pk_parse_keyfile returned -0x%04x\n", -rc );
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        goto finish;
    }
    fflush(stdout);
    memset(buf, 0, sizeof(buf));
    /* 2.3 sign data */
    /* For RSA, md_alg may be MBEDTLS_MD_NONE if hash_len != 0. For ECDSA, md_alg may never be MBEDTLS_MD_NONE. */
    /* 2.3.1 ecc need select hash padding, calculate hash. */
    hash_len = sign_rom_len;
    rc = mbedtls_user_md_type((unsigned char *)sign_rom, &hash_len, hash, get_mbedtls_scheme(sch));
    if (rc != 0) {
        mbedtls_printf(" failed!\n  hash: md_setup. returned :0x%4X\n", rc);
        ret = -ERROR_CRYPTO_SIGN_FAILED;
        goto finish;
    }
    /* 2.3.2 gen ecdsaa handler */
    rc = mbedtls_pk_sign(&pk, get_mbedtls_scheme(sch), hash, hash_len,
                         buf, &outlen, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (rc != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_ecc_sign returned -0x%04x\n", -rc );
        ret = -ERROR_CRYPTO_SIGN_FAILED;
        goto finish;
    }
    /* 2.4 mv data to result text */
    *result_len = outlen;
    memcpy(result, buf, *result_len);
    ret = ERROR_NONE;

    finish:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    if (fp != NULL)
        fclose(fp);
    return ret;
}

int mbedtls_pk_ecc_verified(const unsigned char *sign_rom, size_t sign_rom_len,
                            const unsigned char *result, size_t result_len,
                            SCHEME_TYPE sch,
                            const unsigned char *pub_pem_file)
{
    int ret = ERROR_NONE;
    int rc = MBEDTLS_EXIT_SUCCESS;
    FILE *fp = NULL;
    mbedtls_pk_context pk;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    const char *pers = "mbedtls_ecc_verify";
    size_t hash_len = 0;

    /* 1. check input condition. */
    if (sign_rom == NULL || sign_rom_len == 0 || result == NULL) {
        printf("input parameters error, input is NULL or 0.\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    if (NULL == pub_pem_file) {
        printf("input pem_file name is invalid\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    fp = fopen((const char*)pub_pem_file, "r");
    if (NULL == fp) {
        printf("input pem_file is not exit.\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    fclose(fp);
    fp = NULL;

    /* 2. using the mbedtls interface to verify msg. */
    /* 2.1 init random */
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    rc = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
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
    rc = mbedtls_pk_parse_public_keyfile(&pk, pub_pem_file);
    if (rc != 0) {
        printf( " failed\n  ! mbedtls_pk_parse_public_keyfile returned -0x%04x\n", -rc );
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        goto finish;
    }
    fflush(stdout);
    memset(buf, 0, sizeof(buf));
    /* 2.3 encrypt data */
    /* 2.3.1 caculate hash */
    hash_len = result_len;
    rc = mbedtls_user_md_type(result, &hash_len, hash, get_mbedtls_scheme(sch));
    if (rc != 0) {
        mbedtls_printf("caculate hash failed, ret = 0x%4x\n", rc);
        ret = -ERROR_CRYPTO_SIGN_FAILED;
        goto finish;
    }
    rc = mbedtls_pk_verify(&pk, MBEDTLS_MD_MD5,
                           hash, hash_len,
                           sign_rom, sign_rom_len);
    if (rc != 0) {
        printf( " failed\n  ! mbedtls_ecc_verify returned -0x%04x\n", -rc );
        ret = -ERROR_CRYPTO_VERIFY_FAILED;
        goto finish;
    }
    ret = ERROR_NONE;
    finish:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    if (fp != NULL)
        fclose(fp);
    return ret;
}

/*This function using the mbedtls_ecdsa interface*/

int mbedtls_ecdsa_signature(const unsigned char *sign_rom, size_t sign_rom_len,
                             unsigned char *result, size_t *result_len,
                             SCHEME_TYPE sch,
                             const unsigned char *pem_file, const unsigned char *passwd)
{
    int ret = ERROR_NONE;
    int rc = MBEDTLS_EXIT_SUCCESS;
    FILE *fp = NULL;
    mbedtls_pk_context pk;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_ecdsa_context ctx;
    mbedtls_ecp_keypair *ec_key = NULL;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    size_t hash_len = 0;
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    const char *pers = "mbedtls_ecdsa_verify";
    size_t outlen = 0;

    /* 1. check input condition. */
    if (sign_rom == NULL || result == NULL || sign_rom_len == 0) {
        printf("input parameters error, input is NULL or 0.\n");
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
    /* 2. using the mbedtls interface to sign msg. */
    /* 2.1 init random */
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ecdsa_init(&ctx);
    rc = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                &entropy, (const unsigned char *) pers,
                                strlen(pers));
    if (rc != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n",
                        (unsigned int) -rc );
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    /* 2.2 read the private key */
    mbedtls_pk_init(&pk);
    rc = mbedtls_pk_parse_keyfile(&pk, pem_file, passwd);
    if (rc != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_pk_parse_keyfile returned -0x%04x\n", -rc );
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        goto finish;
    }
    ec_key = mbedtls_pk_ec(pk);
    if (ec_key == NULL) {
        mbedtls_printf(" failed\n  ! mbedtls pk convert to ec failed\n");
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        goto finish;
    }
    rc = mbedtls_ecdsa_from_keypair(&ctx, ec_key);
    if (rc != 0) {
        mbedtls_printf("  failed\n, mbedtls)ecdsa_from_keypair failed! ret = %d\n", rc);
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        goto finish;
    }
    fflush(stdout);
    memset(buf, 0, sizeof(buf));
    /* 2.3 sign data */
    /* For RSA, md_alg may be MBEDTLS_MD_NONE if hash_len != 0. For ECDSA, md_alg may never be MBEDTLS_MD_NONE. */
    /* 2.3.1 ecc need select hash padding, calculate hash. */
    hash_len = sign_rom_len;
    rc = mbedtls_user_md_type((unsigned char *)sign_rom, &hash_len, hash, get_mbedtls_scheme(sch));
    if (rc != 0) {
        mbedtls_printf(" failed!\n  hash: md_setup. returned :0x%4X\n", rc);
        ret = -ERROR_CRYPTO_SIGN_FAILED;
        goto finish;
    }
    /* 2.3.2 gen ecdsaa handler */
    rc = mbedtls_ecdsa_write_signature(&ctx, get_mbedtls_scheme(sch),
                                       hash, hash_len,
                                       buf, &outlen, mbedtls_ctr_drbg_random,
                                       &ctr_drbg);
    if (rc != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_ecdsa_sign returned -0x%04x\n", -rc );
        ret = -ERROR_CRYPTO_SIGN_FAILED;
        goto finish;
    }
    /* 2.4 mv data to result text */
    *result_len = outlen;
    memcpy(result, buf, *result_len);
    ret = ERROR_NONE;

    finish:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_ecdsa_free(&ctx);
    mbedtls_entropy_free(&entropy);
    if (fp != NULL)
        fclose(fp);
    return ret;
}

int mbedtls_ecdsa_verified(const unsigned char *sign_rom, size_t sign_rom_len,
                           const unsigned char *result, size_t result_len,
                           SCHEME_TYPE sch,
                           const unsigned char *pub_pem_file)
{
    int ret = ERROR_NONE;
    int rc = MBEDTLS_EXIT_SUCCESS;
    FILE *fp = NULL;
    mbedtls_pk_context pk;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    const char *pers = "mbedtls_ecc_verify";
    size_t hash_len = 0;
    mbedtls_ecdsa_context ctx;
    mbedtls_ecp_keypair *key = NULL;

    /* 1. check input condition. */
    if (sign_rom == NULL || sign_rom_len == 0 || result == NULL) {
        printf("input parameters error, input is NULL or 0.\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    if (NULL == pub_pem_file) {
        printf("input pem_file name is invalid\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    fp = fopen((const char*)pub_pem_file, "r");
    if (NULL == fp) {
        printf("input pem_file is not exit.\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    fclose(fp);
    fp = NULL;

    /* 2. using the mbedtls interface to verify msg. */
    /* 2.1 init random */
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ecdsa_init(&ctx);
    rc = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
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
    rc = mbedtls_pk_parse_public_keyfile(&pk, pub_pem_file);
    if (rc != 0) {
        printf( " failed\n  ! mbedtls_pk_parse_public_keyfile returned -0x%04x\n", -rc );
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        goto finish;
    }
    key = mbedtls_pk_ec(pk);
    if (key == NULL) {
       mbedtls_printf("failed!\n mbedtls_pk_ec failed\n");
       ret = -ERROR_CRYPTO_READ_KEY_FAILED;
       goto finish;
    }
    rc = mbedtls_ecdsa_from_keypair(&ctx, key);
    if (rc != 0) {
        mbedtls_printf("failed\n mbedtls_ecdsa_from_keypair failed\n");
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        goto finish;
    }
    fflush(stdout);
    memset(buf, 0, sizeof(buf));
    /* 2.3 encrypt data */
    /* 2.3.1 caculate hash */
    hash_len = result_len;
    rc = mbedtls_user_md_type(result, &hash_len, hash, get_mbedtls_scheme(sch));
    if (rc != 0) {
        mbedtls_printf("caculate hash failed, ret = 0x%4x\n", rc);
        ret = -ERROR_CRYPTO_SIGN_FAILED;
        goto finish;
    }
    rc = mbedtls_ecdsa_read_signature(&ctx,
                                      hash, hash_len,
                                      sign_rom, sign_rom_len);
    if (rc != 0) {
        printf( " failed\n  ! mbedtls_ecc_verify returned -0x%04x\n", -rc );
        ret = -ERROR_CRYPTO_VERIFY_FAILED;
        goto finish;
    }
    ret = ERROR_NONE;
    finish:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_ecdsa_free(&ctx);
    if (fp != NULL)
        fclose(fp);
    return ret;
}
