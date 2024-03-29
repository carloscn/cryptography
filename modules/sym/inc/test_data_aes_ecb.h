#ifndef MBEDLTS_TEST_DATA_AES_ECB_H
#define MBEDLTS_TEST_DATA_AES_ECB_H

static const unsigned char aes_test_ecb_enc[16] = {
        0xC3,0x4C,0x05,0x2C,0xC0,0xDA,0x8D,0x73,0x45,0x1A,0xFE,0x5F,0x03,0xBE,0x29,0x7F
};

static const unsigned char aes_test_ecb_key[16] = {
        0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,0xAB,0xF7,0x15,0x88,0x09,0xCF,0x4F,0x3C
};

static const unsigned char aes_test_ecb_dec[16] = {
        0x55,0x5c,0x82,0x24,0xe2,0xc9,0x58,0x73,0x12,0x08,0x5b,0xfb,0x4e,0xcb,0x04,0xb8
};

#endif //MBEDLTS_TEST_DATA_AES_ECB_H
