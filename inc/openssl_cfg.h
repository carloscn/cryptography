//
// Created by carlos on 2020/11/4.
//

#ifndef CARLOS_OPENMBED_OPENSSL_CFG_H
#define CARLOS_OPENMBED_OPENSSL_CFG_H

#define OPSSL_OK    1
#define OPSSL_FAIL  -1
#define UPDATE_BULK_SIZE  4096
#include <stdbool.h>

#define RSA_PADDING_PKCS1_SIZE 11
/* OAEP padding takes 42 bytes */
#define RSA_PADDING_OAEP_PKCS1_SIZE 42

#endif //CARLOS_OPENMBED_OPENSSL_CFG_H
