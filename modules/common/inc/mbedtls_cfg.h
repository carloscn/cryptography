//
// Created by carlos on 2020/11/4.
//

#ifndef CARLOS_OPENMBED_MBEDTLS_CFG_H
#define CARLOS_OPENMBED_MBEDTLS_CFG_H

#include "cfg.h"

#define RSA_PADDING_PKCS1_SIZE 11
/* OAEP padding takes 42 bytes */
#define RSA_PADDING_OAEP_PKCS1_SIZE 42

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */
#include "mbedtls/error.h"
#define RECV_TIME_OUT   (5000)   /*5s*/

#endif //CARLOS_OPENMBED_MBEDTLS_CFG_H
