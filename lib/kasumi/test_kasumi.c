#include "test_kasumi.h"
#include "kasumi.h"

void test_f9_1();
void test_f9_2();

#define ARRAY_SIZE(x)       ((size_t)(sizeof(x)/sizeof(x[0])))

static int check_arrary(u8 *a, u8 *b, size_t size)
{
    size_t i = 0;
    for (i = 0; i < size; i ++) {
        if (a[i] != b[i]) {
            return -1;
        }
    }
    return 0;
}

static void PRINTF_ARRAYprintf_arrary(u8 *a, size_t size, const unsigned char *msg)
{
    size_t i = 0;
    printf(msg);
    for (i = 0; i < size; i ++) {
        printf("0x%2x,", a[i]);
    }
    printf("\n");
}

static int check_pass(int e)
{
    if (!e) {
        printf("Result Passed!\n");
    }else{
        printf("Result Failed!\n");
    }
}
void test_f8_1()
{
    u8 *result = NULL;
    unsigned int expected_result = 0;
    int count = 4199901990;
    int bearer = 3;
    int direct = 0;
    u8 data[] = {
            0xad,0x9c,'D',0x1f,0x89,0x0b,'8',0xc4,'W',0xa4,0x9d,'B',0x14,0x07,0xe8
    };
    u8 o_data[] = {
            0xad,0x9c,'D',0x1f,0x89,0x0b,'8',0xc4,'W',0xa4,0x9d,'B',0x14,0x07,0xe8
    };
    u8 output[] = {0x9b,0xc9,',',0xa8,0x03,0xc6,'{','(',0xa1,0x1a,'K',0xee,'Z',0x0c,'%'};
    u8 key[] = {'Z',0xcb,0x1d,'d','L','\r','Q',' ','N',0xa5,0xf1,'E',0x10,0x10,0xd8,'R',0xFF,0xFF,0xFF};
    int bitlen = 120;
    int i = 0;
#if 0
    f8(key,count,bearer,direct,data,bitlen);
    PRINTF_ARRAY(output, ARRAY_SIZE(output), "En Except:");
    PRINTF_ARRAY(data, ARRAY_SIZE(data), "En Result:");
    CK_PASS(CK_ARRAY(data, output, ARRAY_SIZE(data)));

    f8(key,count,bearer,direct,data,bitlen);
    PRINTF_ARRAY(o_data, ARRAY_SIZE(o_data), "De Except:");
    PRINTF_ARRAY(data, ARRAY_SIZE(data), "De Result:");
    CK_PASS(CK_ARRAY(o_data, data, ARRAY_SIZE(o_data)));
#endif
}

void test_f9_1()
{
    u8 *result;
    unsigned int expected_result = 0xf63bd72c;
    int count = 0x38a6f056;
    int fresh = 0x05d2ec49;
    int dir = 0;
    int len = 189;
    u8 data[] = { 0x6B, 0x22, 0x77, 0x37, 0x29, 0x6f, 0x39, 0x3c,
                  0x80, 0x79, 0x35, 0x3e, 0xdc, 0x87, 0xe2, 0xe8,
                  0x05, 0xd2, 0xec, 0x49, 0xa4, 0xf2, 0xd8, 0xe0};
    u8 ik[16] = { 0x2b, 0xd6, 0x45, 0x9f, 0x82, 0xc5, 0xb3, 0x00,
                  0x95, 0x2c, 0x49, 0x10, 0x48, 0x81, 0xff, 0x48 };

    result = f9(ik, count, fresh, dir, data, len);

    printf(" Expected result: %08x\n", expected_result);
    printf(" Actual result  : %02x%02x%02x%02x\n", result[0], result[1], result[2], result[3]);


}

void test_f9_2()
{
    u8 *result;
    unsigned int expected_result = 0x46e00d4b;
    int count = 0x38a6f056;
    int fresh = 0xb8aefda9;
    int dir = 0;
    int len = 88;
    u8 data[] = { 0x33, 0x32, 0x34, 0x62, 0x63, 0x39, 0x38, 0x61,
                  0x37, 0x34, 0x79 };
    u8 ik[16] = { 0x2b, 0xd6, 0x45, 0x9f, 0x82, 0xc5, 0xb3, 0x00,
                  0x95, 0x2c, 0x49, 0x10, 0x48, 0x81, 0xff, 0x48 };

    result = f9(ik, count, fresh, dir, data, len);

    printf(" Expected result: %08x\n", expected_result);
    printf(" Actual result  : %02x%02x%02x%02x\n", result[0], result[1], result[2], result[3]);

}

int test_kasumi_entry()
{
    test_f9_1();
    test_f9_2();
    test_f8_1();
    return 0;
}