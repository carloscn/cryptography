//
// Created by carlos on 2020/11/4.
//

#ifndef CARLOS_OPENMBED_MBEDTLS_CFG_H
#define CARLOS_OPENMBED_MBEDTLS_CFG_H

#include "cfg.h"

#define RSA_PADDING_PKCS1_SIZE 11
/* OAEP padding takes 42 bytes */
#define RSA_PADDING_OAEP_PKCS1_SIZE 42

#define RECV_TIME_OUT   (5000)   /*5s*/

#endif //CARLOS_OPENMBED_MBEDTLS_CFG_H
