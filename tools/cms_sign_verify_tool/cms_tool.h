#ifndef _CMS_TOOL_H
#define _CMS_TOOL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <openssl/cms.h>
#include <openssl/bio.h>

#define LOG_DEBUG printf("[CMS_TOOL] "); printf

/** Hash Digetst Algorithm */
typedef enum hash_alg
{
    SHA_1 = 0,          /**< SHA-1 Digest Algorithm */
    SHA_256,            /**< SHA-256 Digest Algorithm */
    SHA_384,            /**< SHA-384 Digest Algorithm */
    SHA_512,            /**< SHA-512 Digest Algorithm */
    INVALID_DIGEST      /**< Invalid Digest Algorithm */
} hash_alg_t;

#define TRUE                      1 /**< Success val returned by functions */
#define FALSE                     0 /**< Failure val returned by functions */

#define X509_UTCTIME_STRING_BYTES 13 /**< Expected length of validity period
                                       *   strings in X.509 certificates using
                                       *   UTCTime format
                                       */
#define X509_GENTIME_STRING_BYTES 15 /**< Expected length of validity period
                                       *   strings in X.509 certificates using
                                       *   Generalized Time format
                                       */
#define PEM_FILE_EXTENSION        ".pem"   /* PEM file extention */
#define PEM_FILE_EXTENSION_BYTES  4        /* Length of pem extention */

/* Message digest string definitions */
#define HASH_ALG_SHA1             "sha1"   /**< String macro for sha1 */
#define HASH_ALG_SHA256           "sha256" /**< String macro for sha256 */
#define HASH_ALG_SHA384           "sha384" /**< String macro for sha384 */
#define HASH_ALG_SHA512           "sha512" /**< String macro for sha512 */
#define HASH_ALG_INVALID          "null"   /**< String macro for invalid hash */

/* Message digest length definitions */
#define HASH_BYTES_SHA1           20   /**< Size of SHA1 output bytes */
#define HASH_BYTES_SHA256         32   /**< Size of SHA256 output bytes */
#define HASH_BYTES_SHA384         48   /**< Size of SHA384 output bytes */
#define HASH_BYTES_SHA512         64   /**< Size of SHA512 output bytes */
#define HASH_BYTES_MAX            HASH_BYTES_SHA512

/* X509 certificate definitions */
#define X509_USR_CERT             0x0 /**< User certificate */
#define X509_CA_CERT              0x1 /**< CA certificate */


#define UNUSED(expr)                (void)(expr)

#define CAL_SUCCESS                 ( 0) /* Operation completed successfully */
#define CAL_FILE_NOT_FOUND          (-1) /* Error when file does not exist   */
#define CAL_INVALID_SIG_DATA_SIZE   (-2) /* Error when sig data size invalid */
#define CAL_FAILED_FILE_CREATE      (-3) /* Error unable to create file      */
#define CAL_MAC_LEN_INCORRECT       (-4) /* Error MAC len is incorrect       */
#define CAL_INVALID_ARGUMENT        (-5) /* Error argument passed is invalid */
#define CAL_CRYPTO_API_ERROR        (-6) /* Error with openssl API           */
#define CAL_INSUFFICIENT_BUFFER_LEN (-7) /* Buffer length is not sufficient  */
#define CAL_DATA_COMPARE_FAILED     (-8) /* Data comparison operation failed */
#define CAL_RAND_SEED_ERROR         (-9) /* Failure to run rand_seed         */
#define CAL_RAND_API_ERROR         (-10) /* Failure in RAND_bytes            */
#define CAL_NO_CRYPTO_API_ERROR    (-11) /* Error when Encryption is disabled*/
#define CAL_INVALID_SIGNATURE      (-12) /* Error when verifying isignature  */
#define CAL_INSUFFICIENT_MEMORY    (-13) /* Buffer length is not sufficient  */
#define CAL_LAST_ERROR            (-100) /* Max error codes for adapt layer  */

#define FILE_BUF_SIZE             (1024) /* 1K buf for file read/file write  */

#define MAX_AES_KEY_LENGTH          (32) /* Max bytes in AES key             */
#define AES_BLOCK_BYTES             (16)           /**< Max. AES block bytes */
#define FLAG_BYTES                   (1)                  /**< Bytes in Flag */
#define BYTE_SIZE_BITS               (8)       /**< Number of bits in a byte */
#define MAX_ERR_STR_BYTES           (120)       /**< Max. error string bytes */
#define SIGNATURE_BUFFER_SIZE (1024)

#define MAX_ERROR_STR_LEN     (512)
#define MIN_NUM_CLI_ARGS      3 /* Minimum number of command line arguments */
#define WORD_ALIGN(x) (((x + (4-1)) / 4) * 4) /**< Aligns x to next word */
#define RNG_SEED_BYTES        (128) /* MAX bytes to seed RNG */

int32_t
gen_sig_data_cms(const char *in_file,
                 const char *cert_file,
                 const char *key_file,
                 const char *sig_out_name,
                 hash_alg_t hash_alg,
                 uint8_t *sig_buf,
                 size_t *sig_buf_bytes);

int32_t verify_sig_data_cms(const char *in_file,
                            const char *cert_ca,
                            const char *cert_signer,
                            const char *sig_file,
                            hash_alg_t hash_alg);

int32_t cms_to_buf(CMS_ContentInfo *cms,
                   BIO * bio_in,
                   uint8_t *data_buffer,
                   size_t *data_buffer_size,
                   int32_t flags);

int32_t get_NID(hash_alg_t hash_alg);
X509_STORE *load_cert_chain(const char *file);


#endif /* _CMS_TOOL_H */
