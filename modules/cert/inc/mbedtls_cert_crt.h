//
// Created by carlos on 2021/2/1.
//

#ifndef CARLOS_OPENMBED_MBEDTLS_CERT_CRT_H
#define CARLOS_OPENMBED_MBEDTLS_CERT_CRT_H
#include "mbedtls_common.h"
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>

#define DFL_ISSUER_CRT          ""
#define DFL_REQUEST_FILE        ""
#define DFL_SUBJECT_KEY         "subject.key"
#define DFL_ISSUER_KEY          "ca.key"
#define DFL_SUBJECT_PWD         ""
#define DFL_ISSUER_PWD          ""
#define DFL_OUTPUT_FILENAME     "cert.crt"
#define DFL_SUBJECT_NAME        "CN=Cert,O=mbed TLS,C=UK"
#define DFL_ISSUER_NAME         "CN=CA,O=mbed TLS,C=UK"
#define DFL_NOT_BEFORE          "20010101000000"
#define DFL_NOT_AFTER           "20301231235959"
#define DFL_SERIAL              "1"
#define DFL_SELFSIGN            0
#define DFL_IS_CA               0
#define DFL_MAX_PATHLEN         -1
#define DFL_KEY_USAGE           0
#define DFL_NS_CERT_TYPE        0
#define DFL_VERSION             3
#define DFL_AUTH_IDENT          1
#define DFL_SUBJ_IDENT          1
#define DFL_CONSTRAINTS         1
#define DFL_DIGEST              MBEDTLS_MD_SHA256

#define USAGE \
    "\n usage: cert_write param=<>...\n"                \
    "\n acceptable parameters:\n"                       \
    USAGE_CSR                                           \
    "    subject_key=%%s          default: subject.key\n"   \
    "    subject_pwd=%%s          default: (empty)\n"       \
    "    subject_name=%%s         default: CN=Cert,O=mbed TLS,C=UK\n"   \
    "\n"                                                \
    "    issuer_crt=%%s           default: (empty)\n"       \
    "                            If issuer_crt is specified, issuer_name is\n"  \
    "                            ignored!\n"                \
    "    issuer_name=%%s          default: CN=CA,O=mbed TLS,C=UK\n"     \
    "\n"                                                \
    "    selfsign=%%d             default: 0 (false)\n"     \
    "                            If selfsign is enabled, issuer_name and\n" \
    "                            issuer_key are required (issuer_crt and\n" \
    "                            subject_* are ignored\n"   \
    "    issuer_key=%%s           default: ca.key\n"        \
    "    issuer_pwd=%%s           default: (empty)\n"       \
    "    output_file=%%s          default: cert.crt\n"      \
    "    serial=%%s               default: 1\n"             \
    "    not_before=%%s           default: 20010101000000\n"\
    "    not_after=%%s            default: 20301231235959\n"\
    "    is_ca=%%d                default: 0 (disabled)\n"  \
    "    max_pathlen=%%d          default: -1 (none)\n"     \
    "    md=%%s                   default: SHA256\n"        \
    "                            Supported values (if enabled):\n"      \
    "                            MD2, MD4, MD5, RIPEMD160, SHA1,\n" \
    "                            SHA224, SHA256, SHA384, SHA512\n" \
    "    version=%%d              default: 3\n"            \
    "                            Possible values: 1, 2, 3\n"\
    "    subject_identifier=%%s   default: 1\n"             \
    "                            Possible values: 0, 1\n"   \
    "                            (Considered for v3 only)\n"\
    "    authority_identifier=%%s default: 1\n"             \
    "                            Possible values: 0, 1\n"   \
    "                            (Considered for v3 only)\n"\
    "    basic_constraints=%%d    default: 1\n"             \
    "                            Possible values: 0, 1\n"   \
    "                            (Considered for v3 only)\n"\
    "    key_usage=%%s            default: (empty)\n"       \
    "                            Comma-separated-list of values:\n"     \
    "                            digital_signature\n"     \
    "                            non_repudiation\n"       \
    "                            key_encipherment\n"      \
    "                            data_encipherment\n"     \
    "                            key_agreement\n"         \
    "                            key_cert_sign\n"  \
    "                            crl_sign\n"              \
    "                            (Considered for v3 only)\n"\
    "    ns_cert_type=%%s         default: (empty)\n"       \
    "                            Comma-separated-list of values:\n"     \
    "                            ssl_client\n"            \
    "                            ssl_server\n"            \
    "                            email\n"                 \
    "                            object_signing\n"        \
    "                            ssl_ca\n"                \
    "                            email_ca\n"              \
    "                            object_signing_ca\n"     \
    "\n"

int mbedtls_gen_crt_file();

#endif //CARLOS_OPENMBED_MBEDTLS_CERT_CRT_H
