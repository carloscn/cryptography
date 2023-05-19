#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <strings.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>

#include "cms_tool.h"

#define ENABLE_VERIFY 1
static int32_t count = 0;
static char signed_file_name[256];

void display_error(const char *err)
{
    fprintf(stderr, "Error: %s\n", err);
}

#define DUMP_WIDTH 16
static void bio_dump(const char *s, int len)
{
    char buf[160+1] = {0};
    char tmp[20] = {0};
    unsigned char ch;
    int32_t i, j, rows;

#ifdef TRUNCATE
    int32_t trunc = 0;
    for(; (len > 0) && ((s[len-1] == ' ') || (s[len-1] == '\0')); len--)
        trunc++;
#endif

    rows = (len / DUMP_WIDTH);
    if ((rows * DUMP_WIDTH) < len)
        rows ++;
    for (i = 0; i < rows; i ++) {
        /* start with empty string */
        buf[0] = '\0';
        sprintf(tmp, "%04x - ", i * DUMP_WIDTH);
        strcpy(buf, tmp);
        for (j = 0; j < DUMP_WIDTH; j ++) {
            if (((i * DUMP_WIDTH) + j) >= len) {
                strcat(buf,"   ");
            } else {
                ch = ((unsigned char)*(s + i * DUMP_WIDTH + j)) & 0xff;
                sprintf(tmp, "%02x%c" , ch, j == 7 ? '-':' ');
                strcat(buf, tmp);
            }
        }
        strcat(buf, "  ");
        for(j = 0;j < DUMP_WIDTH;j ++) {
            if (((i * DUMP_WIDTH) + j) >= len)
                break;
            ch = ((unsigned char)*(s + i * DUMP_WIDTH + j)) & 0xff;
            sprintf(tmp, "%c", ((ch >= ' ')&&(ch <= '~')) ? ch : '.');
            strcat(buf, tmp);
        }
        strcat(buf, "\n");
        printf("%s", buf);
    }
#ifdef TRUNCATE
    if (trunc > 0) {
        sprintf(buf,"%04x - <SPACES/NULS>\n",len+trunc);
        printf("%s", buf);
    }
#endif
}

char* get_digest_name(hash_alg_t hash_alg)
{
    char *hash_name = NULL;    /**< Ptr to return address of string macro */
    switch(hash_alg) {
        case SHA_1:
            hash_name = HASH_ALG_SHA1;
            break;
        case SHA_256:
            hash_name = HASH_ALG_SHA256;
            break;
        case SHA_384:
            hash_name = HASH_ALG_SHA384;
            break;
        case SHA_512:
            hash_name = HASH_ALG_SHA512;
            break;
        default:
            hash_name = HASH_ALG_INVALID;
            break;
    }
    return hash_name;
}

void utils_print_bio_array(uint8_t *buffer, size_t len, char* msg)
{
    printf("\n");
    printf("%s: the len is %zu\n", msg, len);
    bio_dump((const char *)buffer, len);
    printf("\n");
}

int32_t get_NID(hash_alg_t hash_alg)
{
    return OBJ_txt2nid(get_digest_name(hash_alg));
}

int32_t cms_to_buf(CMS_ContentInfo *cms, BIO * bio_in, uint8_t * data_buffer,
                            size_t * data_buffer_size, int32_t flags)
{
    int32_t err_value = CAL_SUCCESS;
    BIO * bio_out = NULL;
    BUF_MEM buffer_memory;            /**< Used with BIO functions */

    buffer_memory.length = 0;
    buffer_memory.data = (char*)data_buffer;
    buffer_memory.max = *data_buffer_size;

    do {
        if (!(bio_out = BIO_new(BIO_s_mem()))) {
            display_error("Unable to allocate CMS signature result memory");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        BIO_set_mem_buf(bio_out, &buffer_memory, BIO_NOCLOSE);

        /* Convert cms to der format */
        if (!i2d_CMS_bio_stream(bio_out, cms, bio_in, flags)) {
            display_error("Unable to convert CMS signature to DER format");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Get the size of bio out in data_buffer_size */
        *data_buffer_size = BIO_ctrl_pending(bio_out);
    } while(0);

    if (bio_out)
        BIO_free(bio_out);
    return err_value;
}

static int copy_file(const char *in, const char *out)
{
    char cmd[1024];
    sprintf(cmd, "cp -rf %s %s", in, out);
    return system(cmd);
}

static int check_verified_signer(CMS_ContentInfo* cms, X509_STORE* store)
{
    int i, ret = 1;

    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    STACK_OF(CMS_SignerInfo) *infos = CMS_get0_SignerInfos(cms);
    STACK_OF(X509)* cms_certs = CMS_get1_certs(cms);

    if (!ctx) {
        LOG_DEBUG("Failed to allocate verification context\n");
        return ret;
    }

    for (i = 0; i < sk_CMS_SignerInfo_num(infos) && ret != 0; ++i) {
        CMS_SignerInfo *si = sk_CMS_SignerInfo_value(infos, i);
        X509 *signer = NULL;

        CMS_SignerInfo_get0_algs(si, NULL, &signer, NULL, NULL);
        if (!X509_STORE_CTX_init(ctx, store, signer, cms_certs)) {
            LOG_DEBUG("Failed to initialize signer verification operation\n");
            break;
        }

        X509_STORE_CTX_set_default(ctx, "smime_sign");
        if (X509_verify_cert(ctx) > 0) {
            LOG_DEBUG("Verified signature %d in signer sequence\n", i);
            ret = 0;
        } else {
            LOG_DEBUG("Failed to verify certificate %d in signer sequence\n", i);
        }

        X509_STORE_CTX_cleanup(ctx);
    }

    X509_STORE_CTX_free(ctx);

    return ret;
}

static int cms_verify_callback(int ok, X509_STORE_CTX *ctx) {
    int cert_error = X509_STORE_CTX_get_error(ctx);

    if (!ok) {
        switch (cert_error) {
        case X509_V_ERR_CERT_HAS_EXPIRED:
        case X509_V_ERR_CERT_NOT_YET_VALID:
            ok = 1;
            break;
        default:
            break;
        }
    }

    return ok;
}

static X509*
read_certificate(const char* filename)
{
    BIO  *bio_cert = NULL; /**< OpenSSL BIO ptr */
    X509 *cert = NULL;     /**< X.509 certificate data structure */
    FILE *fp = NULL;       /**< File pointer for DER encoded file */
    /** Points to expected location of ".pem" filename extension */
    const char *temp = filename + strlen(filename) -
                       PEM_FILE_EXTENSION_BYTES;

    bio_cert = BIO_new(BIO_s_file());
    if (bio_cert == NULL)
    {
        return NULL;
    }

    /* PEM encoded */
    if (!strncasecmp(temp, PEM_FILE_EXTENSION, PEM_FILE_EXTENSION_BYTES))
    {
        if (BIO_read_filename(bio_cert, filename) <= 0)
        {
            BIO_free(bio_cert);
            return NULL;
        }

        cert = PEM_read_bio_X509(bio_cert, NULL, 0, NULL);
    }
    /* DER encoded */
    else
    {
        /* Open the DER file and load it into a X509 object */
        fp = fopen(filename, "rb");
        if (NULL == fp) return NULL;
        cert = d2i_X509_fp(fp, NULL);
        fclose(fp);
    }

    BIO_free(bio_cert);
    return cert;
}

X509_STORE *load_cert_chain(const char *file)
{
    X509_STORE *castore = X509_STORE_new();
    if (!castore) {
        return NULL;
    }

    /*
     * Set error callback function for verification of CRTs and CRLs in order
     * to ignore some errors depending on configuration
     */
    X509_STORE_set_verify_cb(castore, cms_verify_callback);

    BIO *castore_bio = BIO_new_file(file, "r");
    if (!castore_bio) {
        LOG_DEBUG("failed: BIO_new_file(%s)\n", file);
        return NULL;
    }

    int crt_count = 0;
    X509 *crt = NULL;
    do {
        crt = PEM_read_bio_X509(castore_bio, NULL, 0, NULL);
        if (crt) {
            crt_count++;
            char *subj = X509_NAME_oneline(X509_get_subject_name(crt), NULL, 0);
            char *issuer = X509_NAME_oneline(X509_get_issuer_name(crt), NULL, 0);
            LOG_DEBUG("Read PEM #%d: %s %s\n", crt_count, issuer, subj);
            free(subj);
            free(issuer);
            if (X509_STORE_add_cert(castore, crt) == 0) {
                LOG_DEBUG("Adding certificate to X509_STORE failed\n");
                BIO_free(castore_bio);
                X509_STORE_free(castore);
                return NULL;
            }
        }
    } while (crt);
    BIO_free(castore_bio);

    if (crt_count == 0) {
        X509_STORE_free(castore);
        return NULL;
    }
    LOG_DEBUG("The crt_count is %d\n", crt_count);

    return castore;
}

int32_t verify_sig_data_cms(const char *in_file,
                            const char *cert_ca,
                            const char *cert_signer,
                            const char *sig_file,
                            hash_alg_t hash_alg)
{
    BIO             *bio_in = NULL;   /**< BIO for in_file data */
    BIO             *bio_sigfile = NULL;   /**< BIO for sigfile data */
    X509_STORE      *store = NULL;     /**< Ptr to X509 certificate read data */
    X509            *signer_cert = NULL;
    CMS_ContentInfo *cms = NULL;      /**< Ptr used with openssl API */
    const EVP_MD    *sign_md = NULL;  /**< Ptr to digest name */
    int32_t err_value = CAL_SUCCESS;  /**< Used for return value */
    int32_t rc = 0;
    /** Array to hold error string */
    char err_str[MAX_ERR_STR_BYTES];
    /* flags set to match Openssl command line options for generating
     *  signatures
     */
    int32_t         flags = CMS_DETACHED | CMS_NOCERTS |
                            CMS_NOSMIMECAP | CMS_BINARY;

    if (NULL == in_file ||
        NULL == cert_ca ||
        NULL == cert_signer ||
        NULL == sig_file ||
        hash_alg >= INVALID_DIGEST) {
        display_error("Input param error!\n");
        return CAL_INVALID_ARGUMENT;
    }

    /* Set signature message digest alg */
    sign_md = EVP_get_digestbyname(get_digest_name(hash_alg));
    if (sign_md == NULL) {
        display_error("Invalid hash digest algorithm");
        return CAL_INVALID_ARGUMENT;
    }

    do
    {
        store = load_cert_chain(cert_ca);
        if (store == NULL) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                     "Cannot open certificates file %s", cert_ca);
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        signer_cert = read_certificate(cert_signer);
        if (!signer_cert) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                     "Cannot open certificate file %s", cert_signer);
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Read signature Data */
        if (!(bio_sigfile = BIO_new_file(sig_file, "rb"))) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                     "Cannot open signature file %s", sig_file);
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        flags |= CMS_NO_SIGNER_CERT_VERIFY;

        /* Parse the DER-encoded CMS message */
        cms = d2i_CMS_bio(bio_sigfile, NULL);
        if (!cms) {
            display_error("Cannot be parsed as DER-encoded CMS signature blob.\n");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        if (!CMS_add1_cert(cms, signer_cert)) {
            display_error("Cannot be inserted signer_cert into cms.\n");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Open the content file (data which was signed) */
        if (!(bio_in = BIO_new_file(in_file, "rb"))) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                     "Cannot open data which was signed  %s", in_file);
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        rc = CMS_verify(cms, NULL, store, bio_in, NULL, flags);
        if (!rc) {
            display_error("Failed to verify the file!\n");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        if (check_verified_signer(cms, store)) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                     "Authentication of all signatures failed!\n");
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        LOG_DEBUG("Verified OK!\n");

    } while(0);

    /* Print any Openssl errors */
    if (err_value != CAL_SUCCESS) {
        ERR_print_errors_fp(stderr);
    }

    /* Close everything down */
    if (cms) CMS_ContentInfo_free(cms);
    if (store) X509_STORE_free(store);
    if (bio_in) BIO_free(bio_in);
    if (bio_sigfile)   BIO_free(bio_sigfile);

    return err_value;
}

static void chomp(char *s)
{
    while(*s && *s != '\n' && *s != '\r') s++;
    *s = 0;
}

static int get_passcode_to_key_file(char *buf, int size, int rwflag, void *userdata)
{
    FILE * password_fp;
    char * ptr_to_last_slash;
    char key_file_path[255];
    char *key_file = (char *)userdata;

    UNUSED(rwflag);

    /* Initialize the temporary path */
    memset(key_file_path,0,255);

    /*
     * Get the folder where the password file is present.
     * The file is located in the same folder than the keys used for signature.
     * Start by searching for the last occurance of '/' in the path of
     * a key installed by a CSF command and passed through *userdata.
     */
    ptr_to_last_slash = strrchr(key_file, '/');

    /* Copy from beginning to ptr_to_last_slash into key_file_path */
    if(ptr_to_last_slash != NULL)
    {
        strncpy(key_file_path, key_file, (ptr_to_last_slash -
                               key_file + 1));
    }

    /* Concatenate with key_pass.txt to form the complete path */
    strcat(key_file_path, "key_pass.txt");

    /*
     * This particular implementation assumes file key_file.txt to be present
     * in keys folder with password string.
     */
    password_fp = fopen(key_file_path, "r");
    if (password_fp == NULL)
    {
        /* Cannot open password file, it could be that keys are not encrypted
         * return 0 for password size */
        LOG_DEBUG("Warning: No private key password file [key_pass.txt]. " \
                  "If the private key has password, the private key will be loaded failed!\n\n");
        return 0;
    }

    fgets(buf, size, password_fp);
    chomp(buf);

    return strlen(buf);
}

static EVP_PKEY*
read_private_key(const char *filename, pem_password_cb *password_cb,
                 const char *password)
{
    BIO      *private_key = NULL; /**< OpenSSL BIO ptr */
    EVP_PKEY *pkey;               /**< Private Key data structure */
    /** Points to expected location of ".pem" filename extension */
    const char *temp = filename + strlen(filename) -
                       PEM_FILE_EXTENSION_BYTES;

    /* Read Private key */
    private_key = BIO_new(BIO_s_file( ));
    if (!private_key)
    {
        return NULL;
    }

    /* Set BIO to read from the given filename */
    if (BIO_read_filename(private_key, filename) <= 0)
    {
        BIO_free(private_key);
        return NULL;
    }

    if (!strncasecmp(temp, PEM_FILE_EXTENSION, PEM_FILE_EXTENSION_BYTES))
    {
        /* Read Private key - from PEM encoded file */
        pkey = PEM_read_bio_PrivateKey(private_key, NULL, password_cb,
                                       (char *)password);
        if (!pkey)
        {
            BIO_free(private_key);
            return NULL;
        }
    }
    else
    {
        pkey = d2i_PKCS8PrivateKey_bio (private_key, NULL, password_cb,
                                        (char *)password );
        if (!pkey)
        {
            BIO_free(private_key);
            return NULL;
        }
    }
    return pkey;
}

int32_t
gen_sig_data_cms(const char *in_file,
                 const char *cert_file,
                 const char *key_file,
                 const char *sig_out_name,
                 hash_alg_t hash_alg,
                 uint8_t *sig_buf,
                 size_t *sig_buf_bytes)
{
    BIO             *bio_in = NULL;   /**< BIO for in_file data */
    X509            *cert = NULL;     /**< Ptr to X509 certificate read data */
    EVP_PKEY        *key = NULL;      /**< Ptr to key read data */
    CMS_ContentInfo *cms = NULL;      /**< Ptr used with openssl API */
    const EVP_MD    *sign_md = NULL;  /**< Ptr to digest name */
    int32_t err_value = CAL_SUCCESS;  /**< Used for return value */
    /** Array to hold error string */
    char err_str[MAX_ERR_STR_BYTES];
    /* flags set to match Openssl command line options for generating
     *  signatures
     */
    int32_t         flags = CMS_DETACHED | CMS_NOCERTS |
                            CMS_NOSMIMECAP | CMS_BINARY;

    if (NULL == in_file ||
        NULL == cert_file ||
        NULL == key_file ||
        NULL == sig_out_name ||
        NULL == sig_buf ||
        NULL == sig_buf_bytes ||
        hash_alg >= INVALID_DIGEST) {
        display_error("Input param error!\n");
        return CAL_INVALID_ARGUMENT;
    }

    /* Set signature message digest alg */
    sign_md = EVP_get_digestbyname(get_digest_name(hash_alg));
    if (sign_md == NULL) {
        display_error("Invalid hash digest algorithm");
        return CAL_INVALID_ARGUMENT;
    }

    do
    {
        cert = read_certificate(cert_file);
        if (!cert) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                     "Cannot open certificate file %s", cert_file);
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Read key */
        key = read_private_key(key_file,
                           (pem_password_cb *)get_passcode_to_key_file,
                           key_file);
        if (!key) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                     "Cannot open key file %s", key_file);
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Read Data to be signed */
        if (!(bio_in = BIO_new_file(in_file, "rb"))) {
            snprintf(err_str, MAX_ERR_STR_BYTES-1,
                     "Cannot open data file %s", in_file);
            display_error(err_str);
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }
        /* Generate CMS Signature - can only use CMS_sign if default
         * MD is used which is SHA1 */
        flags |= CMS_PARTIAL;

        cms = CMS_sign(NULL, NULL, NULL, bio_in, flags);
        if (!cms) {
            display_error("Failed to initialize CMS signature");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        if (!CMS_add1_signer(cms, cert, key, sign_md, flags)) {
            display_error("Failed to generate CMS signature");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Finalize the signature */
        if (!CMS_final(cms, bio_in, NULL, flags)) {
            display_error("Failed to finalize CMS signature");
            err_value = CAL_CRYPTO_API_ERROR;
            break;
        }

        /* Write CMS signature to output buffer - DER format */
        err_value = cms_to_buf(cms, bio_in, sig_buf, sig_buf_bytes, flags);
    } while(0);

    do {
        BIO *yy = BIO_new_file(sig_out_name, "wb");
        BIO_write(yy, sig_buf, *sig_buf_bytes);
        BIO_free(yy);
    } while (0);

    /* Print any Openssl errors */
    if (err_value != CAL_SUCCESS) {
        ERR_print_errors_fp(stderr);
    }

    /* Close everything down */
    if (cms)      CMS_ContentInfo_free(cms);
    if (cert)     X509_free(cert);
    if (key)      EVP_PKEY_free(key);
    if (bio_in)   BIO_free(bio_in);

    return err_value;
}

// $ cms_tool sign image_file_name signer_cert signer_private_key signature_file_name
// $ cms_tool verify image_file_name signer_cert certs_store_ca sigature_file_name

static void print_help()
{
    LOG_DEBUG("cms_tool usage: \n");
    LOG_DEBUG("For sign data: \n");
    LOG_DEBUG("       $ cms_tool sign image_file_name signer_cert signer_private_key signature_file_name\n");
    LOG_DEBUG("For verify data: \n");
    LOG_DEBUG("       $ cms_tool verify image_file_name signer_cert certs_store_ca sigature_file_name\n");
}

int32_t main(int argc, char* argv[])
{
    int32_t ret = -1;

    if (argc < 6) {
        LOG_DEBUG("input error!\n");
        print_help();
        return ret;
    }

    char *mode = argv[1];
    char *input_file_name = argv[2];
    char *signer_cert = argv[3];
    char *signer_pk_or_ca_store = argv[4];
    char *signature_file_name = argv[5];

    hash_alg_t hash_alg = SHA_256;

    uint8_t sig[128 * SIGNATURE_BUFFER_SIZE];
    size_t sig_size = SIGNATURE_BUFFER_SIZE;

    if (0 == strcmp(mode, "sign")) {
        LOG_DEBUG("\n-------------------------[Sign infomation]----------------------\n");
        LOG_DEBUG("original file  : %s\n", input_file_name);
        LOG_DEBUG("signature file : %s\n", signature_file_name);
        LOG_DEBUG("signer cert    : %s\n", signer_cert);
        LOG_DEBUG("signer pkey    : %s\n", signer_pk_or_ca_store);
        LOG_DEBUG("hash_alg       : %s\n", "SHA_256");
        LOG_DEBUG("--------------------------------------------------------------------\n\n");
        ret = gen_sig_data_cms(input_file_name,
                               signer_cert,
                               signer_pk_or_ca_store,
                               signature_file_name,
                               hash_alg,
                               sig,
                               &sig_size);
        if (ret != CAL_SUCCESS) {
            LOG_DEBUG("CMS Sign failed!\n");
            return ret;
        }
        LOG_DEBUG("Sign task finish, please checkout signature %s file.\n", signature_file_name);
    } else if (0 == strcmp(mode, "verify")) {
        LOG_DEBUG("\n-------------------------[Verfiy infomation]----------------------\n");
        LOG_DEBUG("original file  : %s\n", input_file_name);
        LOG_DEBUG("signature file : %s\n", signature_file_name);
        LOG_DEBUG("signer cert    : %s\n", signer_cert);
        LOG_DEBUG("ca certs store : %s\n", signer_pk_or_ca_store);
        LOG_DEBUG("hash_alg       : %s\n", "SHA_256");
        LOG_DEBUG("--------------------------------------------------------------------\n\n");
        ret = verify_sig_data_cms(input_file_name,
                                  signer_pk_or_ca_store,
                                  signer_cert,
                                  signature_file_name,
                                  hash_alg);
        if (ret != CAL_SUCCESS) {
            LOG_DEBUG("CMS Verify failed!\n");
            return ret;
        }
        LOG_DEBUG("Verify task finish!\n");
    } else {
        LOG_DEBUG("input error in mode [%s]!\n", mode);
        print_help();
        return -1;
    }

    return ret;
}