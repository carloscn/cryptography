//
// Created by carlos on 2021/1/11.
//

#include "openssl_gen_dh.h"
#if version
int openssl_gen_dh_prime(const char *out_file, int prim_len)
{
    int ret = ERROR_NONE;
    int rc = OPSSL_OK;

    if (out_file == NULL) {
        printf("  . Failed, input file name buffer, returned NULL, line %d\n",
               __LINE__);
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }

    DH *dh_ctx = NULL;
    BIGNUM *p = NULL, *x = NULL;
    char *buffer = NULL;
    FILE *f = NULL;
    size_t w_len = 0;

    printf("Openssl Generate the DH prime file %s\n", out_file);
    dh_ctx = DH_new();
    if (dh_ctx == NULL) {
        printf("  . Failed, DH_new(), returned NULL, line %d\n",
               __LINE__);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    /*
     * DH_generate_parameters_ex() generates Diffie-Hellman parameters
     * that can be shared among a group of users, and stores them in the
     * provided DH structure. The pseudo-random number generator must be
     * seeded prior to calling DH_generate_parameters().
     *
     * *prime_len is the length in bits of the safe prime to be generated.
     * *generator is a small number > 1, typically 2 or 5.
     * */
    rc = DH_generate_parameters_ex(dh_ctx, prim_len, 2, NULL);
    if (rc != OPSSL_OK) {
        printf("  . Failed, DH_genertate_prarmters_ex(), returned %d, line %d\n",
               rc, __LINE__);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    rc = DH_check(dh_ctx, &rc);
    if (rc != OPSSL_OK) {
        printf("  . Failed, DH_check(), returned %d, line %d\n",
               rc, __LINE__);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    p = DH_get0_p(dh_ctx);
    if (p == NULL) {
        printf("  . Failed, DH_get0_p(), returned NULL, line %d\n",
               __LINE__);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    x = BN_dup(p);
    if (x == NULL) {
        printf("  . Failed, BN_dup(), returned NULL, line %d\n",
               __LINE__);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    /* convert BN to buffer */
    f = fopen(out_file, "wb");
    if (f == NULL) {
        printf("  . Failed, fopen %s, returned NULL, line %d\n",
               out_file, __LINE__);
        ret = -ERROR_COMMON_FILE_OPEN_FAILED;
        goto finish;
    }
    buffer = (char*)malloc((BN_num_bytes(x) + 1) * sizeof(char));
    if (buffer == NULL) {
        printf("  . Failed, malloc failed(), returned NULL, line %d\n",
               __LINE__);
        ret = -ERROR_COMMON_MALLOC_FAILED;
        goto finish;
    }
    buffer[BN_num_bytes(x)] = '\0';
    rc = BN_bn2bin(x, buffer);
    w_len = fwrite(buffer, 1, rc, f);
    if (w_len != rc) {
        printf("  . Failed, fwrite failed, returned len = %d, line %d\n",
               w_len, __LINE__);
        ret = -ERROR_COMMON_FILE_WRITE_FAILED;
        goto finish;
    }
    printf("Openssl gen DH prime finish to %s: %s\n", out_file, buffer);

    finish:
    if (f != NULL)
        fclose(f);
    if (p != NULL)
        BN_free(p);
    if (x != NULL)
        BN_free(x);
    if (dh_ctx != NULL)
        DH_free(dh_ctx);
    if (buffer != NULL)
        free(buffer);
    return ret;
}
#endif