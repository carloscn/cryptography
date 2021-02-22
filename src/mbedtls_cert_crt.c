//
// Created by carlos on 2021/2/1.
//

#include "mbedtls_cert_crt.h"

struct options
{
    const char *issuer_crt;     /* filename of the issuer certificate   */
    const char *request_file;   /* filename of the certificate request  */
    const char *subject_key;    /* filename of the subject key file     */
    const char *issuer_key;     /* filename of the issuer key file      */
    const char *subject_pwd;    /* password for the subject key file    */
    const char *issuer_pwd;     /* password for the issuer key file     */
    const char *output_file;    /* where to store the constructed CRT   */
    const char *subject_name;   /* subject name for certificate         */
    const char *issuer_name;    /* issuer name for certificate          */
    const char *not_before;     /* validity period not before           */
    const char *not_after;      /* validity period not after            */
    const char *serial;         /* serial number string                 */
    int selfsign;               /* selfsign the certificate             */
    int is_ca;                  /* is a CA certificate                  */
    int max_pathlen;            /* maximum CA path length               */
    int authority_identifier;   /* add authority identifier to CRT      */
    int subject_identifier;     /* add subject identifier to CRT        */
    int basic_constraints;      /* add basic constraints ext to CRT     */
    int version;                /* CRT version                          */
    mbedtls_md_type_t md;       /* Hash used for signing                */
    unsigned char key_usage;    /* key usage flags                      */
    unsigned char ns_cert_type; /* NS cert type                         */
} opt;


int mbedtls_gen_crt_file()
{
    int rc = MBEDTLS_EXIT_SUCCESS;
    int ret = ERROR_NONE;

    int i = 0;
    char buf[4096];
    mbedtls_x509write_cert crt;
    mbedtls_entropy_context entropy;
    mbedtls_mpi serial;
    mbedtls_x509_crt issuer_crt;
    mbedtls_pk_context loaded_issuer_key, loaded_subject_key;
    mbedtls_pk_context *issuer_key = &loaded_issuer_key,
                       *subject_key = &loaded_subject_key;
#if defined(MBEDTLS_X509_CSR_PARSE_C)
    char subject_name[256];
    mbedtls_x509_csr csr;
#endif
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "csr example req";
    FILE *file = NULL;
    size_t len = 0;

    mbedtls_x509write_crt_init( &crt );
    mbedtls_pk_init( &loaded_issuer_key );
    mbedtls_pk_init( &loaded_subject_key );
    mbedtls_mpi_init( &serial );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
#if defined(MBEDTLS_X509_CSR_PARSE_C)
    mbedtls_x509_csr_init( &csr );
#endif
    mbedtls_x509_crt_init( &issuer_crt );
    memset( buf, 0, sizeof buf);

    opt.issuer_crt          = DFL_ISSUER_CRT;
    opt.request_file        = DFL_REQUEST_FILE;
    opt.subject_key         = DFL_SUBJECT_KEY;
    opt.issuer_key          = DFL_ISSUER_KEY;
    opt.subject_pwd         = DFL_SUBJECT_PWD;
    opt.issuer_pwd          = DFL_ISSUER_PWD;
    opt.output_file         = DFL_OUTPUT_FILENAME;
    opt.subject_name        = DFL_SUBJECT_NAME;
    opt.issuer_name         = DFL_ISSUER_NAME;
    opt.not_before          = DFL_NOT_BEFORE;
    opt.not_after           = DFL_NOT_AFTER;
    opt.serial              = DFL_SERIAL;
    opt.selfsign            = DFL_SELFSIGN;
    opt.is_ca               = DFL_IS_CA;
    opt.max_pathlen         = DFL_MAX_PATHLEN;
    opt.key_usage           = DFL_KEY_USAGE;
    opt.ns_cert_type        = DFL_NS_CERT_TYPE;
    opt.version             = DFL_VERSION - 1;
    opt.md                  = DFL_DIGEST;
    opt.subject_identifier   = DFL_SUBJ_IDENT;
    opt.authority_identifier = DFL_AUTH_IDENT;
    opt.basic_constraints    = DFL_CONSTRAINTS;

    rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char*)pers,
                               strlen(pers));
    if (rc != 0) {
        ret = -ERROR_CRYPTO_INIT_FAILED;
        mbedtls_strerror(rc, buf, 1024);
        mbedtls_printf("  . Failed, mbedtls_ctr_drbg_seed, returned NULL, line %d\n",
                       __LINE__);
        goto finish;
    }
    mbedtls_printf(" . OK, prng. [done]\n");

finish:
    mbedtls_pk_free(&loaded_issuer_key);
    mbedtls_pk_free(&loaded_subject_key);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_x509write_crt_free(&crt);
    mbedtls_mpi_free(&serial);
#if defined(MBEDTLS_X509_CSR_PARSE_C)
    mbedtls_x509_csr_free(&csr);
#endif
    if (file != NULL)
        fclose(file);
    return ret;
}