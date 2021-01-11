//
// Created by carlos on 2021/1/11.
//

#ifndef CARLOS_OPENMBED_OPENSSL_GEN_DH_H
#define CARLOS_OPENMBED_OPENSSL_GEN_DH_H

#include "openssl_common.h"
#include <openssl/dh.h>
#include <openssl/bn.h>

int openssl_gen_dh_prime(const char *out_file, int prim_len);

#endif //CARLOS_OPENMBED_OPENSSL_GEN_DH_H
