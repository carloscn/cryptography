//
// Created by 魏昊晨 on 2020/9/23.
//

#ifndef WARM_OPENSSL_UTILS_H
#define WARM_OPENSSL_UTILS_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdio.h>

#define DUMP_HEX(A) _print_hex("hex list :", A, strlen(A))

void _print_hex(const char *title, const unsigned char buf[], size_t len);

#endif //WARM_OPENSSL_UTILS_H
