//
// Created by carlos on 2020/12/23.
//

#ifndef CARLOS_OPENMBED_OPENSSL_COMMON_H
#define CARLOS_OPENMBED_OPENSSL_COMMON_H

#include "openssl_cfg.h"
#include <openssl/ssl.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>

EVP_MD* get_evp_scheme(SCHEME_TYPE sch);



#endif //CARLOS_OPENMBED_OPENSSL_COMMON_H
