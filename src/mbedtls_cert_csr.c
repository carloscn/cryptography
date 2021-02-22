//
// Created by carlos on 2021/2/1.
//
#include "mbedtls_cert_csr.h"

struct options
{
    const char *filename;       /* filename of the key file             */
    const char *password;       /* password for the key file            */
    int debug_level;            /* level of debugging                   */
    const char *output_file;    /* where to store the constructed key file  */
    const char *subject_name;   /* subject name for certificate request */
    unsigned char key_usage;    /* key usage flags                      */
    int force_key_usage;        /* Force adding the KeyUsage extension  */
    unsigned char ns_cert_type; /* NS cert type                         */
    int force_ns_cert_type;     /* Force adding NsCertType extension    */
    mbedtls_md_type_t md_alg;   /* Hash algorithm used for signature.   */
} opt;

int mbedtls_gen_csr_file()
{
    int rc = MBEDTLS_EXIT_SUCCESS;
    int ret = ERROR_NONE;

    int i = 0;
    char buf[4096];
    mbedtls_pk_context key;
    mbedtls_x509write_csr req;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "csr example req";
    FILE *file = NULL;
    size_t len = 0;

    memset(buf, 0, sizeof(buf));
    opt.filename = DFL_RSAPEMKEY;
    opt.password = DFL_PASSWORD;
    opt.debug_level = DFL_DEBUG_LEVEL;
    opt.output_file = DFL_OUTPUT_FILENAME;
    opt.subject_name = DFL_SUBJECT_NAME;
    opt.key_usage = DFL_KEY_USAGE;
    opt.force_key_usage = DFL_FORCE_KEY_USAGE;
    opt.ns_cert_type = DFL_NS_CERT_TYPE;
    opt.md_alg = DFL_MD_ALG;

    /* 1. Init mbedtls */
    mbedtls_x509write_csr_init(&req);
    mbedtls_pk_init(&key);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char*)pers,
                              strlen(pers));
    if (rc != 0) {
        ret = -ERROR_CRYPTO_INIT_FAILED;
        mbedtls_printf("  . Failed, mbedtls_ctr_drbg_seed, returned NULL, line %d\n",
                       __LINE__);
        goto finish;
    }
    mbedtls_printf(" . OK, prng. [done]\n");

    /* 2. Config cert 509 */
    /* 2.1 config the HASH MD scheme */
    mbedtls_x509write_csr_set_md_alg(&req, opt.md_alg);
    /* 2.2 config the key usage */
    mbedtls_x509write_csr_set_key_usage(&req, opt.key_usage);
    /* 2.3 config the ns cert type */
    mbedtls_x509write_csr_set_ns_cert_type(&req, opt.ns_cert_type);
    /* 2.4 load RSA key file */
    rc = mbedtls_pk_parse_keyfile(&key, opt.filename, opt.password);
    if (rc != 0) {
        ret = -ERROR_CRYPTO_INIT_FAILED;
        mbedtls_printf("  . Failed, 2.4 load RSA key file, returned NULL, line %d\n",
                       __LINE__);
        goto finish;
    }
    mbedtls_x509write_csr_set_key(&req, &key);
    mbedtls_printf(" . INIT OK, write config cert. [done]\n");

    /* 3. Write certificate request file */
    /* 3.1 write csr pem */
    rc = mbedtls_x509write_csr_pem(&req, buf, sizeof(buf), mbedtls_ctr_drbg_random,
                                   &ctr_drbg);
    if (rc != 0) {
        ret = -ERROR_CRYPTO_INIT_FAILED;
        mbedtls_printf("  . Failed, 3.1 write csr pem file, returned NULL, line %d\n",
                       __LINE__);
        goto finish;
    }
    /* 3.2 write to file */
    file = fopen(DFL_OUTPUT_FILENAME, "w");
    if (file == NULL) {
        ret = -ERROR_COMMON_FILE_OPEN_FAILED;
        mbedtls_printf("  . Failed, 3.2 write pem file, returned NULL, line %d\n",
                       __LINE__);
        goto finish;
    }
    len = strlen(buf);
    if (fwrite(buf, 1, len, file) != len) {
        ret = -ERROR_COMMON_FILE_WRITE_FAILED;
        mbedtls_printf("  . Failed, 3.2 write pem file, returned NULL, line %d\n",
                       __LINE__);
        goto finish;
    }
    fclose(file); file = NULL;
    mbedtls_printf(" . Write OK, write to %s finish. [done]", DFL_OUTPUT_FILENAME);

    finish:
    mbedtls_pk_free(&key);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_x509write_csr_free(&req);
    if (file != NULL)
        fclose(file);
    return ret;
}
