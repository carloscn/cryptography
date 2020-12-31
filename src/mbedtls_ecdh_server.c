//
// Created by carlos on 2020/12/30.
//

#include "mbedtls_ecdh_server.h"

#define CUR_ID MBEDTLS_ECP_DP_CURVE25519

int mbedtls_ecdh_server_entry()
{
    int ret = ERROR_NONE;
    int rc = MBEDTLS_EXIT_SUCCESS;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecdh_context ctx;
    mbedtls_aes_context aes;
    mbedtls_mpi X;
    size_t n, buflen;
    uint8_t *pers = "random";
    uint8_t hash[64];
    uint8_t *msg = "hello world!";
    FILE *f = NULL;
    uint8_t *ip = "192.168.3.79";
    uint8_t *port = "5556";
    uint8_t client_ip[255];
    uint8_t buffer[4096] = {'\0'};
    size_t signed_len = 0;
    uint8_t buf2[2];
    int net_len = 0;
    int sig_len = 0;

    mbedtls_ecdh_init(&ctx);
    mbedtls_aes_init(&aes);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_mpi_init(&X);
    /*
     * 1. Initialize random number
     * */
    mbedtls_printf("Run the gen ecdh share parameter X...\n");
    fflush(stdout);
    rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char*)pers, strlen(pers));
    if (rc != 0) {
        mbedtls_printf("  . Failed, mbedtls_ctr_drbg_seed, returned %d, line %d\n",
                       rc, __LINE__);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    mbedtls_printf("  . init: random initialize finish.\n");

    rc = mbedtls_ecp_group_load(&ctx.grp, CUR_ID);
    if (rc != 0) {
        mbedtls_printf("  . Failed, ecp_group_load, returned %d, line %d\n",
                       rc, __LINE__);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    mbedtls_printf("  . init: load ecp group.\n");

    rc = mbedtls_ecdh_gen_public(&ctx.grp, &ctx.d, &ctx.Q,
                                 mbedtls_ctr_drbg_random, &ctr_drbg);
    if (rc != 0) {
        mbedtls_printf("  . Failed, ecdh_gen_public, returned %d, line %d\n",
                       rc, __LINE__);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    mbedtls_printf("  . init: ecdh genned public\n");

    f = fopen(ECDHM_PRIME_FILE, "r+");
    if (f == NULL) {
        mbedtls_printf("  . Failed, fopen [%s] failed, returned NULL, line %d\n",
                       ECDHM_PRIME_FILE, __LINE__);
        ret = -ERROR_COMMON_FILE_OPEN_FAILED;
        goto finish;
    }
    rc = mbedtls_mpi_read_file(&X, 16, f);
    if (rc != 0) {
        mbedtls_printf("  . Failed, mpi read file failed, returned %d, line %d\n",
                       rc, __LINE__);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }

    finish:
    mbedtls_ecdh_free(&ctx);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    if (f != NULL) {
        fclose(f);
    }
    return ret;

}