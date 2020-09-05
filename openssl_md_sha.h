//
// Created by 魏昊晨 on 2020/9/5.
//

#ifndef WARM_OPENSSL_OPENSSL_MD_SHA_H
#define WARM_OPENSSL_OPENSSL_MD_SHA_H

#include <openssl/ssl.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/x509.h>
int openssl_md5(unsigned char *content, uint64_t len, unsigned char *out);
int openssl_evp_md5(unsigned char *content, uint64_t len, unsigned char *out);
#endif //WARM_OPENSSL_OPENSSL_MD_SHA_H
