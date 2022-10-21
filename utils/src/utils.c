//
// Created by Carlos on 2020/9/23.
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

int CK_ARRAY(unsigned char *a, unsigned char *b, size_t size)
{
    size_t i = 0;
    for (i = 0; i < size; i ++) {
        if (a[i] != b[i]) {
            return -1;
        }
    }
    return 0;
}

void PRINTF_ARRAY(unsigned char *a, size_t size, const unsigned char *msg)
{
    size_t i = 0;
    printf(msg);
    for (i = 0; i < size; i ++) {
        printf("0x%2x,", a[i]);
    }
    printf("\n");
}

int CK_PASS(int e)
{
    if (!e) {
        printf("Result Passed!\n");
    }else{
        printf("Result Failed!\n");
    }
}