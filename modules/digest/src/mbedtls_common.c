//
// Created by carlos on 2020/12/23.
//

#include "mbedtls_common.h"

mbedtls_md_type_t get_mbedtls_scheme(SCHEME_TYPE sch)
{
    switch (sch) {
        case M_MD5:
            return MBEDTLS_MD_MD5;
        case M_SHA1:
            return MBEDTLS_MD_SHA1;
        case M_SHA224:
            return MBEDTLS_MD_SHA224;
        case M_SHA256:
            return MBEDTLS_MD_SHA256;
        case M_SHA384:
            return MBEDTLS_MD_SHA384;
        case M_SHA512:
            return MBEDTLS_MD_SHA512;
        default:
            return MBEDTLS_MD_NONE;
    }
}