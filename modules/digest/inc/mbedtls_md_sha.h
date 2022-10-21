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



int mbedtls_user_md_str(unsigned char *content, uint64_t len, unsigned char *out, const unsigned char* type);
int mbedtls_user_md_type(unsigned char *content, size_t *len, unsigned char *out, mbedtls_md_type_t type);
#endif //WARM_OPENSSL_MBEDTLS_MD_SHA_H
