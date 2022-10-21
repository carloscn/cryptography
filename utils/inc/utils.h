//
// Created by Carlos on 2020/9/23.
//

#ifndef WARM_OPENSSL_UTILS_H
#define WARM_OPENSSL_UTILS_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdio.h>

#define DUMP_HEX(A) _print_hex("hex list :", A, strlen(A))
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#define UTILS_CHECK(__true_condition__, __ret_code__, __fmt__, ...) \
    do {                                                            \
        if (!(__true_condition__)) {                                \
            printf("")                                              \
        }                                                                \
    } while(0)
void _print_hex(const char *title, const unsigned char buf[], size_t len);

int check_pass(int e);
int check_arrary(unsigned char *a, unsigned char *b, size_t size);
void PRINTF_ARRAY(unsigned char *a, size_t size, const unsigned char *msg);
#define ARRAY_SIZE(x)       ((size_t)(sizeof(x)/sizeof(x[0])))
#endif //WARM_OPENSSL_UTILS_H
