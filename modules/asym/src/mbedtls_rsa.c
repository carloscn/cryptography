//
// Created by carlos on 2020/11/2.
// https://tls.mbed.org/kb/cryptography/asn0-key-structures-in-der-and-pem
// https://tls.mbed.org/kb/how-to/encrypt-and-decrypt-with-rsa
//
#include "mbedtls_rsa.h"

#define KEY_SIZE 512
#define EXPONENT 0x10001L   //RSA_F4

int mbedtls_get_pem_sig_len(const char* keyfile, bool ispriv, void* passwd)
{
    int ret = ERROR_NONE;
    int rc = MBEDTLS_EXIT_SUCCESS;
    FILE *f = NULL;
    uint8_t *pers = "getlen";

    mbedtls_rsa_context *rsa = NULL;
    mbedtls_pk_context pk;

    if (keyfile == NULL) {
        printf("keyfile is NULL\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }

    f = fopen((const char*)keyfile, "r");
    if (NULL == f) {
        printf("input pem_file is not exit.\n");
        ret = -ERROR_COMMON_FILE_OPEN_FAILED;
        goto finish;
    }
    fclose(f);
    f = NULL;

    mbedtls_pk_init(&pk);
    if (ispriv == false)
        rc = mbedtls_pk_parse_public_keyfile(&pk, keyfile);
    else
        rc = mbedtls_pk_parse_keyfile(&pk, keyfile, passwd);
    if (rc != 0) {
        printf( " failed\n  ! mbedtls_pk_parse_public_keyfile returned -0x%04x\n", -ret );
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        goto finish;
    }
    rsa = mbedtls_pk_rsa(pk);
    if (rsa == NULL) {
        mbedtls_printf(" failed\n  ! mbedtls_pk_rsa failed returned -0x%04x\n", -ret);
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        goto finish;
    }
    ret = rsa->len;
    finish:
    if (rsa != NULL)
        mbedtls_rsa_free(rsa);
    mbedtls_pk_free(&pk);
    if (f != NULL)
        fclose(f);
    return ret;
}

int mbedtls_gen_rsa_raw_key_files(const char *pub_keyfile, const char *pri_keyfile,
                                       const unsigned char *passwd, int passwd_len, unsigned int key_size)
{
    FILE *fpub = NULL;
    FILE *fpri = NULL;
    mbedtls_pk_context key;
    int ret = MBEDTLS_EXIT_FAILURE;
    mbedtls_rsa_context rsa;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    const char *pers = "rsa_entryption";

    mbedtls_entropy_init(&entropy);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                &entropy, (const unsigned char*)pers,
                                strlen(pers) );
    if (ret != 0) {
        mbedtls_printf("mbedtls_ctr_drbg_seed failed. ret = %d\n", ret);
        goto finish;
    }
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
    mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );
    mbedtls_printf("Seeding the random number generator\n");
    fflush(stdout);

    mbedtls_printf("Generate the public key...\n");
    ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, key_size,
            EXPONENT);
    if (ret != 0) {
        mbedtls_printf("failed! mbedtls_rsa_gen_key return %d.\n", ret);
        goto finish;
    }

    ret = mbedtls_rsa_export(&rsa, &N, &P, &Q, &D, &E);
    if (ret != 0) {
        mbedtls_printf("failed! mbedtls_rsa_export return %d. \n", ret);
        goto finish;
    }
    ret = mbedtls_rsa_export_crt(&rsa, &DP, &DQ, &QP);
    if (ret != 0) {
        mbedtls_printf("failed! mbedtls_rsa_export ctr return %d\n", ret);
        goto finish;
    }
    fpub = fopen(pub_keyfile, "wb+");
    if (fpub == NULL) {
        mbedtls_printf("failed! fopen rsa_pub.txt.\n");
        goto finish;
    }
    ret = mbedtls_mpi_write_file("N = ", &N, 16, fpub);
    if (ret != 0) {
        mbedtls_printf("failed, mpi write N to file. return %d\n", ret);
        goto finish;
    }
    ret = mbedtls_mpi_write_file("E = ", &E, 16, fpub);
    if (ret != 0) {
        mbedtls_printf("failed, mpi write E to file. return %d\n", ret);
        goto finish;
    }
    mbedtls_printf("generate the private key...\n");
    fpri = fopen(pri_keyfile, "wb+");
    if (fpri == NULL) {
        mbedtls_printf("failed, fopen rsa_pri.txt.");
        goto finish;
    }
    if( ( ret = mbedtls_mpi_write_file( "N = " , &N , 16, fpri ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "E = " , &E , 16, fpri ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "D = " , &D , 16, fpri ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "P = " , &P , 16, fpri ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "Q = " , &Q , 16, fpri ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "DP = ", &DP, 16, fpri ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "DQ = ", &DQ, 16, fpri ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "QP = ", &QP, 16, fpri ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret );
        goto finish;
    }
    ret = MBEDTLS_EXIT_SUCCESS;
finish:
    if( fpub  != NULL )
        fclose( fpub );
    if( fpri != NULL )
        fclose( fpri );
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
    mbedtls_rsa_free( &rsa );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    return ret;
}

int mbedtls_gen_rsa_pem_key_files(const char *pub_keyfile, const char *pri_keyfile,
                                  const unsigned char *passwd, int passwd_len,  unsigned int key_size)
{
    int ret = MBEDTLS_EXIT_SUCCESS;
    mbedtls_pk_context key;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_rsa_context *rsa = NULL;
    const char *pers = "gen_key";
    unsigned char pem_out_buffer[16000];
    size_t buffer_len = 0;
    FILE *pri_fp = NULL;
    FILE *pub_fp = NULL;

    /* 1. pk and mpi data init. */
    mbedtls_printf("[genkey]: Init mpi data.\n");
    mbedtls_mpi_init(&N); mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&E); mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ); mbedtls_mpi_init(&QP);
    mbedtls_pk_init(&key);
    mbedtls_entropy_init(&entropy);
    /* 2. init drbg random for gen key. */
    mbedtls_printf("[genkey]: Init random moudle.\n");
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                &entropy, (const unsigned char*)pers,
                                strlen(pers) );
    if (ret != 0) {
        mbedtls_printf("mbedtls_ctr_drbg_seed failed. ret = %d\n", ret);
        goto finish;
    }
    /* 3. generate key */
    mbedtls_printf("[genkey]: Gening the key pair.\n");
    ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret != 0) {
        mbedtls_printf("failed! mbedtls_pk_setup to RSA. return %d\n", ret);
        goto finish;
    }
    rsa = mbedtls_pk_rsa(key);
    ret = mbedtls_rsa_gen_key(rsa, mbedtls_ctr_drbg_random, &ctr_drbg,
                              key_size, EXPONENT);
    if (ret != 0) {
        mbedtls_printf("failed! mbedtls_rsa_gen_key to Key %d \n", ret);
        goto finish;
    }
    /* 4. save key*/
    mbedtls_printf("[genkey]: Saving private key file\n");

    if( ( ret = mbedtls_rsa_export    ( rsa, &N, &P, &Q, &D, &E ) ) != 0 ||
        ( ret = mbedtls_rsa_export_crt( rsa, &DP, &DQ, &QP ) )      != 0 )
    {
        mbedtls_printf( " failed\n  ! could not export RSA parameters\n\n" );
        goto finish;
    }
    mbedtls_mpi_write_file( "N:  ",  &N,  16, NULL );
    mbedtls_mpi_write_file( "E:  ",  &E,  16, NULL );
    mbedtls_mpi_write_file( "D:  ",  &D,  16, NULL );
    mbedtls_mpi_write_file( "P:  ",  &P,  16, NULL );
    mbedtls_mpi_write_file( "Q:  ",  &Q,  16, NULL );
    mbedtls_mpi_write_file( "DP: ",  &DP, 16, NULL );
    mbedtls_mpi_write_file( "DQ:  ", &DQ, 16, NULL );
    mbedtls_mpi_write_file( "QP:  ", &QP, 16, NULL );
    memset(pem_out_buffer, 0, 16000);
    ret = mbedtls_pk_write_key_pem(&key, pem_out_buffer, 16000);
    if (ret != 0) {
        mbedtls_printf("failed! pk write key pem return %d\n", ret);
        goto finish;
    }
    buffer_len = strlen((char*)pem_out_buffer);
    pri_fp = fopen(pri_keyfile, "w");
    if (pri_fp == NULL) {
        mbedtls_printf("failed! open pri pem file. \n");
        goto finish;
    }
    if (fwrite(pem_out_buffer, 1, buffer_len, pri_fp) != buffer_len) {
        mbedtls_printf("failed! write key pem word len.\n");
        goto finish;
    }
    fclose(pri_fp); pri_fp = NULL;

    /* 5. saving the public key file */
    mbedtls_printf("[genkey]: Saving publibc key file.\n");
    memset(pem_out_buffer, 0, 16000);
    //ret = mbedtls_pk_parse_keyfile(&key, pri_keyfile, NULL);
    ret = mbedtls_pk_write_pubkey_pem(&key, pem_out_buffer, 16000);
    if (ret != 0) {
        mbedtls_printf("failed! mbedtls_pk_write_pubkey_pem return %d\n", ret);
        goto finish;
    }
    buffer_len = strlen((char*)pem_out_buffer);
    pub_fp = fopen(pub_keyfile, "w");
    if (pub_fp == NULL) {
        mbedtls_printf("failed! write key pem file.\n");
        goto finish;
    }
    if (fwrite(pem_out_buffer, 1, buffer_len, pub_fp) != buffer_len) {
        mbedtls_printf("failed! write key pem file length failed!\n");
        goto finish;
    }
    fclose(pub_fp); pub_fp = NULL;
    ret = MBEDTLS_EXIT_SUCCESS;
    mbedtls_printf("[genkey]: genkey finished.\n");
finish:
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
    mbedtls_pk_free( &key );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    if (pri_fp != NULL)
        fclose(pri_fp);
    if (pub_fp != NULL)
        fclose(pub_fp);
    return ret;
}

int mbedtls_rsa_pkcs8_encrypt(const unsigned char *plain_text, size_t plain_len,
                              unsigned char *cipher_text, size_t *cipher_len,
                              unsigned char *pem_file)
{
    int ret = 0;
    FILE *fp = NULL;
    mbedtls_pk_context pk;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    const char *pers = "mbedtls_pk_encrypt";

    /* 1. check input condition. */
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

    /* 2. using the mbedtls interface to encrypt msg. */
    /* note: For a 2048 bit RSA key, the maximum you can encrypt is 245 bytes (or 1960 bits). */
    /* 2.1 init random */
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                 &entropy, (const unsigned char *) pers,
                                 strlen(pers));
    if (ret != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n",
                        (unsigned int) -ret );
        goto finish;
    }
    /* 2.2 read the public key */
    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_public_keyfile(&pk, pem_file);
    if (ret != 0) {
        printf( " failed\n  ! mbedtls_pk_parse_public_keyfile returned -0x%04x\n", -ret );
        goto finish;
    }
    fflush(stdout);
    memset(buf, 0, MBEDTLS_MPI_MAX_SIZE);
    /* 2.3 encrypt data */
    ret = mbedtls_pk_encrypt(&pk, plain_text, plain_len, \
                             buf, cipher_len, \
                             sizeof(buf), \
                             mbedtls_ctr_drbg_random, \
                             &ctr_drbg);
    if (ret != 0) {
        printf( " failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n", -ret );
        goto finish;
    }
    /* 2.4 mv data to cipher text */
    memcpy(cipher_text, buf, *cipher_len);
    ret = MBEDTLS_EXIT_SUCCESS;

finish:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    if (fp != NULL)
        fclose(fp);
    return ret;
}

int mbedtls_rsa_pkcs8_decrypt(const unsigned char *cipher_text, size_t cipher_len,
                              unsigned char *plain_text, size_t *plain_len,
                              const unsigned char *pem_file, const unsigned char *passwd)
{
    int ret = 0;
    FILE *fp = NULL;
    mbedtls_pk_context pk;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    const char *pers = "mbedtls_pk_decrypt";

    /* 1. check input condition. */
    if (plain_text == NULL || cipher_text == NULL || cipher_len == 0) {
        printf("input parameters error, input is NULL or 0.\n");
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

    /* 2. using the mbedtls interface to decrypt msg. */
    /* note: For a 2048 bit RSA key, the maximum you can encrypt is 245 bytes (or 1960 bits). */
    /* 2.1 init random */
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                 &entropy, (const unsigned char *) pers,
                                 strlen(pers));
    if (ret != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n",
                        (unsigned int) -ret );
        goto finish;
    }
    /* 2.2 read the private key */
    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_keyfile(&pk, pem_file, passwd);
    if (ret != 0) {
        printf( " failed\n  ! mbedtls_pk_parse_keyfile returned -0x%04x\n", -ret );
        goto finish;
    }
    fflush(stdout);
    memset(buf, 0, MBEDTLS_MPI_MAX_SIZE);
    /* 2.3 decrypt data */
    ret = mbedtls_pk_decrypt(&pk, cipher_text, cipher_len, \
                             buf, plain_len, \
                             sizeof(buf), \
                             mbedtls_ctr_drbg_random, \
                             &ctr_drbg);
    if (ret != 0) {
        printf( " failed\n  ! mbedtls_pk_decrypt returned -0x%04x\n", -ret );
        goto finish;
    }
    /* 2.4 mv data to plain text */
    memcpy(plain_text, buf, *plain_len);
    ret = MBEDTLS_EXIT_SUCCESS;

finish:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    if (fp != NULL)
        fclose(fp);
    return ret;
}

int mbedtls_rsa_pkcs1_encryption(const unsigned char *plain_text, size_t plain_len,
                                 unsigned char **cipher_text, size_t *cipher_len,
                                 unsigned char *pem_file)
{
    int ret = MBEDTLS_EXIT_FAILURE;
    FILE *fp = NULL;
    mbedtls_rsa_context *rsa = NULL;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk;
    const char *pers = "mbedtls_rsa_pkcs1_encrypt";
    unsigned char * msg_hook = NULL;
    size_t bulk_size = 0, algo_len = 0;
    size_t enc_times = 0, enc_len = 0;
    size_t cacu_len = 0;
    size_t reset_len = 0;
    int padding_mode = 0;
    int i = 0;

    /* 1. check input condition. */
    if (plain_text == NULL || plain_len == 0 ||  *cipher_len == 0) {
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

    /* 2. using the mbedtls interface to encrypt msg. */
    /* note: For a 2048 bit RSA key, the maximum you can encrypt is 245 bytes (or 1960 bits). */
    /* 2.1 init random */
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                 &entropy, (const unsigned char *) pers,
                                 strlen(pers));
    if (ret != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n",
                        (unsigned int) -ret );
        goto finish;
    }
    /* 2.2 read the rsa public key PKCS#1 */
    /* 2.2.1 note hash_id when the MBEDTLS_RSA_PKCS_V21, hash id need select mbedtls_md_type_t. */
    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_public_keyfile(&pk, pem_file);
    if (ret != 0) {
        printf( " failed\n  ! mbedtls_pk_parse_public_keyfile returned -0x%04x\n", -ret );
        goto finish;
    }
    rsa = mbedtls_pk_rsa(pk);
    if (rsa == NULL) {
        mbedtls_printf(" failed\n  ! mbedtls_pk_rsa failed returned -0x%04x\n", -ret);
        goto finish;
    }
    /* padding:	MBEDTLS_RSA_PKCS_V15 or MBEDTLS_RSA_PKCS_V21(OAEP) */
    /* hash id:
     * The hash_id parameter is actually ignored when using MBEDTLS_RSA_PKCS_V15 padding.
     * The chosen hash is always used for OEAP encryption. For PSS signatures,
     * it's always used for making signatures, but can be overriden
     * (and always is, if set to MBEDTLS_MD_NONE) for verifying them.*/
    padding_mode = MBEDTLS_RSA_PKCS_V21;
    mbedtls_rsa_set_padding(rsa, padding_mode, MBEDTLS_MD_MD5);
    fflush(stdout);
    /* 2.3 encrypt data */
    algo_len = mbedtls_pk_get_len(&pk);
    bulk_size = algo_len;
    if (rsa->padding == MBEDTLS_RSA_PKCS_V15) {
        bulk_size -= RSA_PADDING_PKCS1_SIZE;
    } else if (padding_mode == MBEDTLS_RSA_PKCS_V21) {
        bulk_size -= RSA_PADDING_OAEP_PKCS1_SIZE;
    }
    enc_times = (size_t)(plain_len / bulk_size + ((plain_len%bulk_size)?1:0));
    enc_len = enc_times * algo_len;
    *cipher_text = (uint8_t *)malloc(enc_len);
    if (*cipher_text == NULL) {
        ret = -ERROR_COMMON_MALLOC_FAILED;
        mbedtls_printf(" error\n ! malloc cipher text buffer failed! ret = %d\n", ret);
        goto finish;
    }
    *cipher_len = 0;
    reset_len = plain_len;
    msg_hook = plain_text;
    for (i = 0; i < enc_times; i ++) {
        if (reset_len < bulk_size)
            bulk_size = reset_len;
        ret = mbedtls_rsa_pkcs1_encrypt(rsa, mbedtls_ctr_drbg_random, \
                                    &ctr_drbg, MBEDTLS_RSA_PUBLIC,\
                                    bulk_size,
                                    msg_hook, \
                                    (uint8_t*)(*cipher_text + i*algo_len));
        if (ret != 0) {
            printf(" failed\n  ! mbedtls_rsa_pkcs1_encrypt returned -0x%04x\n", -ret);
            goto finish;
        }
        mbedtls_printf("bulk %d , enc len %ld\n", i, bulk_size);
        cacu_len += rsa->len;
        msg_hook += bulk_size;
        reset_len -= bulk_size;
    }
    *cipher_len = cacu_len;
    ret = MBEDTLS_EXIT_SUCCESS;

    finish:
    if (rsa != NULL)
        mbedtls_rsa_free(rsa);
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    if (fp != NULL)
        fclose(fp);
    if (*cipher_text != NULL && ret != MBEDTLS_EXIT_SUCCESS) {
        free(*cipher_text);
        *cipher_text = NULL;
    }
    return ret;
}

int mbedtls_rsa_pkcs1_decryption(const unsigned char *cipher_text, size_t cipher_len,
                                 unsigned char **plain_text, size_t *plain_len,
                                 const unsigned char *pem_file, const unsigned char *passwd)
{
    int ret = 0;
    FILE *fp = NULL;
    mbedtls_rsa_context *rsa = NULL;
    mbedtls_pk_context pk;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    const char *pers = "mbedtls_rsa_pkcs1_decrypt";
    size_t algo_len = 0;
    size_t dec_len = 0;
    size_t out_len = 0;
    int padding_mode = 0;
    int i = 0;

    /* 1. check input condition. */
    if (plain_text == NULL || cipher_text == NULL || cipher_len == 0) {
        printf("input parameters error, input is NULL or 0.\n");
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

    /* 2. using the mbedtls interface to decrypt msg. */
    /* note: For a 2048 bit RSA key, the maximum you can encrypt is 245 bytes (or 1960 bits). */
    /* 2.1 init random */
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                 &entropy, (const unsigned char *) pers,
                                 strlen(pers));
    if (ret != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n",
                        (unsigned int) -ret );
        goto finish;
    }
    /* 2.2 read the public key */
    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_keyfile(&pk, pem_file, passwd);
    if (ret != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_pk_parse_keyfile returned -0x%04x\n", -ret );
        goto finish;
    }
    fflush(stdout);
    rsa = mbedtls_pk_rsa(pk);
    if (rsa == NULL) {
        mbedtls_printf(" failed\n  ! mbedtls_pk_rsa failed returned -0x%04x\n", -ret);
        goto finish;
    }
    /* padding:	MBEDTLS_RSA_PKCS_V15 or MBEDTLS_RSA_PKCS_V21(OAEP) */
    /* hash id:
     * The hash_id parameter is actually ignored when using MBEDTLS_RSA_PKCS_V15 padding.
     * The chosen hash is always used for OEAP encryption. For PSS signatures,
     * it's always used for making signatures, but can be overriden
     * (and always is, if set to MBEDTLS_MD_NONE) for verifying them.*/
    padding_mode = MBEDTLS_RSA_PKCS_V21;
    mbedtls_rsa_set_padding(rsa, padding_mode, MBEDTLS_MD_MD5);
    /* 2.3 decrypt data */
    algo_len = mbedtls_pk_get_len(&pk);
    *plain_text = (uint8_t *)malloc(cipher_len);
    if (*plain_text == NULL) {
        ret = -ERROR_COMMON_MALLOC_FAILED;
        mbedtls_printf(" error\n ! malloc plain text buffer failed! ret = %d\n", ret);
        goto finish;
    }
    *plain_len = 0;
    for (i = 0; i < cipher_len/algo_len; i ++) {
        ret = mbedtls_rsa_pkcs1_decrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, \
                                        MBEDTLS_RSA_PRIVATE, \
                                        &out_len,
                                        (uint8_t *)(cipher_text + i*algo_len), \
                                        (uint8_t *)(*plain_text + dec_len), \
                                        algo_len);
        if (ret != 0) {
            printf(" failed\n  ! mbedtls_pk_decrypt returned -0x%04x\n", -ret);
            goto finish;
        }
        mbedtls_printf("bulk %d, dec len %ld\n", i, out_len);
        dec_len += out_len;
    }
    *plain_len = dec_len;
    ret = MBEDTLS_EXIT_SUCCESS;

    finish:
    if (rsa != NULL)
        mbedtls_rsa_free(rsa);
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    if (fp != NULL)
        fclose(fp);
    if (*plain_text != NULL && ret != MBEDTLS_EXIT_SUCCESS) {
        free(*plain_text);
        *plain_text = NULL;
    }
    return ret;
}

int mbedtls_rsa_pkcs8_signature(const unsigned char *sign_rom, size_t sign_rom_len,
                                unsigned char *result, size_t *result_len,
                                SCHEME_TYPE sch,
                                const unsigned char *priv_pem_file, const unsigned char *passwd)
{
    int ret = MBEDTLS_EXIT_FAILURE;
    FILE *fp = NULL;
    mbedtls_pk_context pk;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    unsigned char hash[64];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    const char *pers = "mbedtls_pk_signature";

    /* 1. check input condition. */
    if (sign_rom == NULL || result == NULL || sign_rom_len == 0) {
        printf("input parameters error, input is NULL or 0.\n");
        ret = -1;
        goto finish;
    }
    if (NULL == priv_pem_file) {
        printf("input pem_file name is invalid\n");
        ret = -1;
        goto finish;
    }
    fp = fopen((const char*)priv_pem_file, "r");
    if (NULL == fp) {
        printf("input pem_file is not exit.\n");
        ret = -1;
        goto finish;
    }
    fclose(fp);
    fp = NULL;

    /* 2. using the mbedtls interface to sign msg. */
    /* 2.1 init random */
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                 &entropy, (const unsigned char *) pers,
                                 strlen(pers));
    if (ret != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n",
                        (unsigned int) -ret );
        goto finish;
    }
    /* 2.2 read the private key */
    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_keyfile(&pk, priv_pem_file, passwd);
    if (ret != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_pk_parse_keyfile returned -0x%04x\n", -ret );
        goto finish;
    }
    fflush(stdout);
    memset(buf, 0, MBEDTLS_MPI_MAX_SIZE);
    /* 2.3 sign data */
    /* For RSA, md_alg may be MBEDTLS_MD_NONE if hash_len != 0. For ECDSA, md_alg may never be MBEDTLS_MD_NONE. */
    /* 2.3.1 ecc need select hash padding, calculate hash. */
    ret = mbedtls_user_md_type(sign_rom, sign_rom_len, hash, get_mbedtls_scheme(sch));
    if (ret != 0) {
        mbedtls_printf(" failed!\n  hash: md_setup. returned :0x%4X\n", ret);
        goto finish;
    }
    /* 2.3.2 sign */
    ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_MD5, hash, sizeof(hash), \
                             buf, result_len, \
                             mbedtls_ctr_drbg_random, \
                             &ctr_drbg);
    if (ret != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_pk_sign returned -0x%04x\n", -ret );
        goto finish;
    }
    /* 2.4 mv data to result text */
    memcpy(result, buf, *result_len);
    ret = MBEDTLS_EXIT_SUCCESS;

    finish:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    if (fp != NULL)
        fclose(fp);
    return ret;
}

int mbedtls_rsa_pkcs8_verified(const unsigned char *sign_rom, size_t sign_rom_len,
                               const unsigned char *result, size_t result_len,
                               SCHEME_TYPE sch,
                               const unsigned char *pub_pem_file)
{
    int ret = 0;
    FILE *fp = NULL;
    mbedtls_pk_context pk;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    unsigned char hash[64];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    const char *pers = "mbedtls_pk_verify";

    /* 1. check input condition. */
    if (sign_rom == NULL || sign_rom_len == 0 || result == NULL) {
        printf("input parameters error, input is NULL or 0.\n");
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
        printf("input pem_file is not exit.\n");
        ret = -1;
        goto finish;
    }
    fclose(fp);
    fp = NULL;

    /* 2. using the mbedtls interface to verify msg. */
    /* 2.1 init random */
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                 &entropy, (const unsigned char *) pers,
                                 strlen(pers));
    if (ret != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n",
                        (unsigned int) -ret );
        goto finish;
    }
    /* 2.2 read the public key */
    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_public_keyfile(&pk, pub_pem_file);
    if (ret != 0) {
        printf( " failed\n  ! mbedtls_pk_parse_public_keyfile returned -0x%04x\n", -ret );
        goto finish;
    }
    fflush(stdout);
    memset(buf, 0, MBEDTLS_MPI_MAX_SIZE);
    /* 2.3 encrypt data */
    /* 2.3.1 caculate hash */
    ret = mbedtls_user_md_type(result, result_len, hash, get_mbedtls_scheme(sch));
    if (ret != 0) {
        mbedtls_printf("caculate hash failed, ret = 0x%4x\n", ret);
        goto finish;
    }
    ret = mbedtls_pk_verify( &pk, MBEDTLS_MD_MD5, hash, sizeof(hash), sign_rom, sign_rom_len);
    if (ret != 0) {
        printf( " failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n", -ret );
        goto finish;
    }
    ret = MBEDTLS_EXIT_SUCCESS;
    mbedtls_printf("mbedtls verify succuss.\n");
    finish:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    if (fp != NULL)
        fclose(fp);
    return ret;
}

int mbedtls_rsa_pkcs1_signature(const unsigned char *sign_rom, size_t sign_rom_len,
                                unsigned char *result, size_t *result_len,
                                SCHEME_TYPE sch,
                                const unsigned char *priv_pem_file, const unsigned char *passwd)
{
    int ret = MBEDTLS_EXIT_FAILURE;
    FILE *fp = NULL;
    mbedtls_pk_context pk;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_rsa_context *rsa = NULL;
    unsigned char hash[64];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    const char *pers = "mbedtls_rsa_pkcs#1_signature";
    size_t res_len = 0;

    /* 1. check input condition. */
    if (sign_rom == NULL || result == NULL || sign_rom_len == 0) {
        printf("input parameters error, input is NULL or 0.\n");
        ret = -1;
        goto finish;
    }
    if (NULL == priv_pem_file) {
        printf("input pem_file name is invalid\n");
        ret = -1;
        goto finish;
    }
    fp = fopen((const char*)priv_pem_file, "r");
    if (NULL == fp) {
        printf("input pem_file is not exit.\n");
        ret = -1;
        goto finish;
    }
    fclose(fp);
    fp = NULL;

    /* 2. using the mbedtls interface to sign msg. */
    /* 2.1 init random */
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                 &entropy, (const unsigned char *) pers,
                                 strlen(pers));
    if (ret != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n",
                        (unsigned int) -ret );
        goto finish;
    }
    /* 2.2 read the private key */
    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_keyfile(&pk, priv_pem_file, passwd);
    if (ret != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_pk_parse_keyfile returned -0x%04x\n", -ret );
        goto finish;
    }
    fflush(stdout);
    memset(buf, 0, MBEDTLS_MPI_MAX_SIZE);
    /* 2.3 sign data */
    /* For RSA, md_alg may be MBEDTLS_MD_NONE if hash_len != 0. For ECDSA, md_alg may never be MBEDTLS_MD_NONE. */
    /* 2.3.1 ecc need select hash padding, calculate hash. */
    res_len = sign_rom_len;
    ret = mbedtls_user_md_type(sign_rom, &res_len, hash, get_mbedtls_scheme(sch));
    if (ret != 0) {
        mbedtls_printf(" failed!\n  hash: md_setup. returned :0x%4X\n", ret);
        goto finish;
    }
    /* 2.3.2 gen rsa handler */
    rsa = mbedtls_pk_rsa(pk);
    if (rsa == NULL) {
        mbedtls_printf(" failed!\n rsa gen failed. return 0x%4X\n", ret);
        goto finish;
    }
    ret = mbedtls_rsa_pkcs1_sign(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, \
                                 MBEDTLS_RSA_PRIVATE, get_mbedtls_scheme(sch),\
                                 (unsigned int)res_len, hash, buf);
    if (ret != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_pkcs1_sign returned -0x%04x\n", -ret );
        goto finish;
    }
    *result_len = rsa->len;
    /* 2.4 mv data to result text */
    memcpy(result, buf, *result_len);
    ret = MBEDTLS_EXIT_SUCCESS;
    finish:
    if (rsa != NULL)
        mbedtls_rsa_free(rsa);
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    if (fp != NULL)
        fclose(fp);
    return ret;
}

int mbedtls_rsa_pkcs1_verified(const unsigned char *sign_rom, size_t sign_rom_len,
                               const unsigned char *result, size_t result_len,
                               SCHEME_TYPE sch,
                               const unsigned char *pub_pem_file)
{
    int ret = 0;
    FILE *fp = NULL;
    mbedtls_pk_context pk;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_rsa_context *rsa = NULL;
    unsigned char hash[64];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    size_t res_len = 0;
    const char *pers = "mbedtls_rsa_pkcs#1_verify";

    /* 1. check input condition. */
    if (sign_rom == NULL || sign_rom_len == 0 || result == NULL) {
        printf("input parameters error, input is NULL or 0.\n");
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
        printf("input pem_file is not exit.\n");
        ret = -1;
        goto finish;
    }
    fclose(fp);
    fp = NULL;

    /* 2. using the mbedtls interface to verify msg. */
    /* 2.1 init random */
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                 &entropy, (const unsigned char *) pers,
                                 strlen(pers));
    if (ret != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n",
                        (unsigned int) -ret );
        goto finish;
    }
    /* 2.2 read the public key */
    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_public_keyfile(&pk, pub_pem_file);
    if (ret != 0) {
        printf( " failed\n  ! mbedtls_pk_parse_public_keyfile returned -0x%04x\n", -ret );
        goto finish;
    }
    fflush(stdout);
    memset(buf, 0, MBEDTLS_MPI_MAX_SIZE);
    /* 2.3 encrypt data */
    /* 2.3.1 caculate hash */
    res_len = result_len;
    ret = mbedtls_user_md_type(result, &res_len, hash, get_mbedtls_scheme(sch));
    if (ret != 0) {
        mbedtls_printf("caculate hash failed, ret = 0x%4x\n", ret);
        goto finish;
    }
    /* 2.3.2 gen rsa */
    rsa = mbedtls_pk_rsa(pk);
    if (rsa == NULL) {
        mbedtls_printf("failed, gen rsa failed return 0x%4x\n", ret);
        goto finish;
    }
    ret = mbedtls_rsa_pkcs1_verify(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, \
                                   MBEDTLS_RSA_PUBLIC, get_mbedtls_scheme(sch),
                                   (unsigned int)res_len, hash, sign_rom);
    if (ret != 0) {
        printf( " failed\n  ! mbedtls_rsa_pkcs1_verify returned -0x%04x\n", -ret );
        goto finish;
    }
    ret = MBEDTLS_EXIT_SUCCESS;
    mbedtls_printf("mbedtls verify succuss.\n");
    finish:
    if (rsa != NULL)
        mbedtls_rsa_free(rsa);
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    if (fp != NULL)
        fclose(fp);
    return ret;
}