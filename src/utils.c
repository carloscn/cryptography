//
// Created by 魏昊晨 on 2020/9/23.
//
#include "utils.h"

void _print_hex(const char *title, const unsigned char buf[], size_t len)
{
    printf("%s: \n", title);
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("0x%02X,", buf[i]);
    }
    printf("\r\n");
}