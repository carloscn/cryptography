//
// Created by carlos on 2020/11/2.
//
#include "mbedtls_rsa.h"

#define KEY_SIZE 512
#define EXPONENT 0x10001L   //RSA_F4

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

int mbedtls_evp_rsa_encrypt(unsigned char *plain_text, size_t plain_len,
                            unsigned char *cipher_text, size_t *cipher_len,
                            unsigned char *pem_file)
{
    int ret = 0;
    FILE *fp = NULL;

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

    /* 2. using the mbedtls lib to encrypt msg. */



    finish:
    return ret;
}
