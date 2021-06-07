#include "test_kasumi.h"
#include "kasumi.h"

void test_f9_1();
void test_f9_2();

int test_kasumi_entry()
{
    test_f9_1();
    test_f9_2();
    return 0;
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
