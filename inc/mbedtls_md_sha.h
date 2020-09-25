//
// Created by 魏昊晨 on 2020/9/5.
//

#ifndef WARM_OPENSSL_MBEDTLS_MD_SHA_H
#define WARM_OPENSSL_MBEDTLS_MD_SHA_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mbedtls/md.h>
#include <mbedtls/config.h>
#include <mbedtls/platform.h>
#include <mbedtls/md4.h>
#include <mbedtls/md5.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

typedef enum digest_scheme_t {
    K_SHA1 = 0,
    K_SHA224,
    K_SHA256,
    K_SHA384,
    K_SHA512,
    K_SM3
} DIGEST_SELECT;

int mbedtls_user_md(unsigned char *content, uint64_t len, unsigned char *out, const char *type);
#endif //WARM_OPENSSL_MBEDTLS_MD_SHA_H
