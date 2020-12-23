//
// Created by carlos on 2020/12/23.
//

#include "openssl_common.h"

EVP_MD* get_evp_scheme(SCHEME_TYPE sch)
{
    switch (sch) {
        case M_MD5:
            return EVP_md5();
        case M_SHA1:
            return EVP_sha1();
        case M_SHA224:
            return EVP_sha224();
        case M_SHA256:
            return EVP_sha256();
        case M_SHA384:
            return EVP_sha384();
        case M_SHA512:
            return EVP_sha512();
        default:
            return NULL;
    }
}