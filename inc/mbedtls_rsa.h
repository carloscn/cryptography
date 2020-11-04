//
// Created by carlos on 2020/11/2.
//

#ifndef CARLOS_OPENMBED_MBEDTLS_RSA_H
#define CARLOS_OPENMBED_MBEDTLS_RSA_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mbedtls/config.h>
#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/platform.h>

int mbedtls_generate_rsa_pem_key_files(const char *pub_keyfile, const char *pri_keyfile,
                                       const unsigned char *passwd, int passwd_len, unsigned int key_size);

#endif //CARLOS_OPENMBED_MBEDTLS_RSA_H
