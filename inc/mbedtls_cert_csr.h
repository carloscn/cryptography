//
// Created by carlos on 2021/2/1.
//
#ifndef CARLOS_OPENMBED_MBEDTLS_CERT_CSR_H
#define CARLOS_OPENMBED_MBEDTLS_CERT_CSR_H
#include "mbedtls_common.h"
/* csr: Certificate signing request file*/
#include <mbedtls/x509_csr.h>

#define DFL_RSAPEMKEY           "rsaprikey.pem"
#define DFL_FILENAME            "keyfile.key"
#define DFL_PASSWORD            NULL
#define DFL_DEBUG_LEVEL         0
#define DFL_OUTPUT_FILENAME     "cert.req"
#define DFL_SUBJECT_NAME        "CN=Cert,O=mbed TLS,C=CN"
#define DFL_KEY_USAGE           0
/*
 * DFL_KEY_USAGE list:
 * MBEDTLS_X509_KU_DIGITAL_SIGNATURE
 * MBEDTLS_X509_KU_NON_REPUDIATION
 * MBEDTLS_X509_KU_KEY_ENCIPHERMENT
 * MBEDTLS_X509_KU_DATA_ENCIPHERMENT
 * MBEDTLS_X509_KU_KEY_AGREEMENT
 * MBEDTLS_X509_KU_KEY_CERT_SIGN
 * MBEDTLS_X509_KU_CRL_SIGN
 * */
#define DFL_FORCE_KEY_USAGE     0
#define DFL_NS_CERT_TYPE        0
/*
 * DFL_NS_CERT_TYPE list:
 * MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT
 * MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER
 * MBEDTLS_X509_NS_CERT_TYPE_EMAIL
 * MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING
 * MBEDTLS_X509_NS_CERT_TYPE_SSL_CA
 * MBEDTLS_X509_NS_CERT_TYPE_EMAIL_CA
 * MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA
 * */
#define DFL_FORCE_NS_CERT_TYPE  0
#define DFL_MD_ALG              MBEDTLS_MD_SHA256

#define USAGE \
    "\n usage: cert_req param=<>...\n"                  \
    "\n acceptable parameters:\n"                       \
    "    filename=%%s         default: keyfile.key\n"   \
    "    password=%%s         default: NULL\n"          \
    "    debug_level=%%d      default: 0 (disabled)\n"  \
    "    output_file=%%s      default: cert.req\n"      \
    "    subject_name=%%s     default: CN=Cert,O=mbed TLS,C=UK\n"   \
    "    key_usage=%%s        default: (empty)\n"       \
    "                        Comma-separated-list of values:\n"     \
    "                          digital_signature\n"     \
    "                          non_repudiation\n"       \
    "                          key_encipherment\n"      \
    "                          data_encipherment\n"     \
    "                          key_agreement\n"         \
    "                          key_cert_sign\n"  \
    "                          crl_sign\n"              \
    "    force_key_usage=0/1  default: off\n"           \
    "                          Add KeyUsage even if it is empty\n"  \
    "    ns_cert_type=%%s     default: (empty)\n"       \
    "                        Comma-separated-list of values:\n"     \
    "                          ssl_client\n"            \
    "                          ssl_server\n"            \
    "                          email\n"                 \
    "                          object_signing\n"        \
    "                          ssl_ca\n"                \
    "                          email_ca\n"              \
    "                          object_signing_ca\n"     \
    "    force_ns_cert_type=0/1 default: off\n"         \
    "                          Add NsCertType even if it is empty\n"    \
    "    md=%%s               default: SHA256\n"       \
    "                          possible values:\n"     \
    "                          MD2, MD4, MD5, RIPEMD160, SHA1,\n" \
    "                          SHA224, SHA256, SHA384, SHA512\n" \
    "\n"

int mbedtls_gen_csr_file();

#endif //CARLOS_OPENMBED_MBEDTLS_CERT_CSR_H

