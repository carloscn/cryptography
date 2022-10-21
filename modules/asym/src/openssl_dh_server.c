//
// Created by carlos on 2020/12/30.
//

#include "openssl_dh_server.h"

int openssl_dh_server_entry(const char* prim_file)
{
    int ret = ERROR_NONE;
    int rc = OPSSL_OK;

    if (prim_file == NULL) {
        printf("  . Failed, input file name buffer, returned NULL, line %d\n",
               __LINE__);
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }

    FILE *f = NULL;
    BIGNUM *x = NULL;
    char *buffer = NULL;
    size_t r_len = 0, file_len = 0;
    /* read x from prim_file */
    f = fopen(prim_file, "rb");
    if (f == NULL) {
        printf("  . Failed, fopen %s, returned NULL, line %d\n",
               prim_file, __LINE__);
        ret = -ERROR_COMMON_FILE_OPEN_FAILED;
        goto finish;
    }
    fseek(f, 0L, SEEK_END);
    file_len = ftell(f);
    if (file_len == 0) {
        printf("  . Failed, ftell %s, returned 0, line %d\n",
               prim_file, __LINE__);
        ret = -ERROR_COMMON_FILE_READ_FAILED;
        goto finish;
    }
    buffer = (char*)OPENSSL_malloc(file_len * sizeof(char));
    if (buffer == NULL) {
        printf("  . Failed, malloc, returned NULL, line %d\n",
               __LINE__);
        ret = -ERROR_COMMON_MALLOC_FAILED;
        goto finish;
    }
    file_len = fread(buffer, 1, r_len, f);
    if (r_len != file_len) {
        printf("  . Failed, fread %s, returned len = %ld, line %d\n",
               prim_file, r_len, __LINE__);
        ret = -ERROR_COMMON_FILE_READ_FAILED;
        goto finish;
    }
#if 0
    x = BN_new();
    if (x == NULL) {
        printf("  . Failed, BN_new(), returned NULL, line %d\n",
               __LINE__);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
#endif
    x = BN_bin2bn(buffer, r_len, x);
    if (x == NULL) {
        printf("  . Failed, BN_bin2bn(), returned NULL, line %d\n",
               __LINE__);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    




    finish:

    return ret;
}