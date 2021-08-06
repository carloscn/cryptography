#ifndef MBEDTLS_TEST_DATA_AES_CBC_H
#define MBEDTLS_TEST_DATA_AES_CBC_H

static const unsigned char aes_test_cbc_enc[256] = {
        0x13,0x9e,0x26,0xaf,0xc5,0x72,0x44,0xbc,0x6d,0x78,0x50,0x66,0x2f,0x66,0x8f,0x8e,
        0x4f,0xa0,0x34,0x03,0x7c,0x72,0x20,0x46,0x12,0xbd,0x7b,0x74,0xbe,0xf7,0x38,0x11,
        0x9d,0xe6,0x03,0x8b,0x4f,0xcc,0x42,0x16,0xa7,0xd0,0x8d,0x9b,0x7d,0x9e,0x10,0x36,
        0x9d,0x38,0x35,0x76,0x31,0xa3,0x23,0x54,0x74,0x1e,0xc1,0x16,0xd3,0x18,0x59,0xfb,
        0xdf,0x2a,0x7b,0xe4,0x2b,0x0d,0xd3,0xa0,0xb2,0x0f,0x9a,0xe9,0x7e,0xc8,0x0e,0x1e,
        0x13,0xea,0x6a,0x20,0xb9,0x0f,0x68,0x06,0xe4,0xb7,0xad,0x7d,0xca,0xb1,0x83,0x10,
        0xa2,0x9e,0x9f,0xd8,0x39,0x47,0x8f,0x7a,0x8f,0x70,0x57,0xbd,0x90,0xef,0xec,0x5f,
        0xb4,0x1e,0x62,0xe8,0xd6,0x35,0xc5,0x87,0x52,0x27,0x94,0xcd,0xe4,0x53,0xeb,0xb5,
        0xa2,0xd9,0x28,0x61,0x34,0x43,0xab,0x5a,0xd9,0xc9,0x38,0x50,0xba,0x35,0x0c,0x4c,
        0x8c,0xd7,0xc7,0xaa,0x79,0x2f,0x0d,0x00,0x27,0x90,0x08,0x04,0x50,0xbe,0xd8,0x7b,
        0x92,0x08,0x9b,0xb7,0x6d,0xe1,0xc2,0x2e,0x13,0xce,0xbd,0xa3,0xd5,0x22,0x46,0xb9,
        0x27,0xee,0x57,0x28,0xe8,0x7a,0x27,0x2f,0x3c,0x2e,0xbe,0xd0,0xfa,0xd1,0xad,0x91,
        0xb4,0xb4,0x2c,0x43,0xce,0x45,0xc0,0xdb,0x73,0x44,0x65,0x57,0xb4,0x4c,0xda,0x4a,
        0xbb,0xc6,0x25,0x8c,0x5f,0x7a,0x24,0xd5,0xac,0xc4,0xc3,0x0a,0xcb,0x7d,0x7e,0x48,
        0x04,0x40,0xba,0x33,0x79,0xca,0x50,0x1d,0x4f,0xf5,0xbd,0x8e,0x4b,0xee,0xef,0xe6,
        0xcd,0x00,0xe7,0x3f,0xd9,0x65,0xd0,0xcc,0x60,0x27,0x80,0x7b,0xe3,0x7e,0x07,0x85
};

static const unsigned char aes_test_cbc_key[16] = {
        0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,0xAB,0xF7,0x15,0x88,0x09,0xCF,0x4F,0x3C
};

static const unsigned char aes_test_cbc_iv[16] = {
        0x55,0x5c,0x82,0x24,0xe2,0xc9,0x58,0x73,0x12,0x08,0x5b,0xfb,0x4e,0xcb,0x04,0xb8
};

static const unsigned char aes_test_cbc_dec[256] = {
        0xb0,0x6a,0x73,0x0c,0x8d,0x5a,0x62,0x73,0x91,0x86,0x65,0x0c,0x96,0xfe,0x67,0x34,
        0x50,0x5f,0x0c,0x11,0x4d,0xe7,0xf0,0xdb,0x0d,0xed,0xbd,0xb6,0xd5,0x90,0xf5,0x93,
        0xe1,0xfb,0x76,0x7e,0xc3,0xdf,0x45,0xa0,0x8c,0x18,0xcf,0xee,0x77,0x9d,0xbe,0x72,
        0xdc,0xe8,0xc8,0x4b,0xb3,0x3a,0xec,0xf3,0x4e,0xdc,0xd6,0xc8,0x63,0x11,0xfd,0xd4,
        0x69,0xbc,0x8c,0xfe,0xf4,0x9b,0xad,0x45,0x4d,0x3e,0x63,0x49,0xce,0xe7,0x81,0x7a,
        0x62,0x58,0xcf,0xc7,0x74,0xc2,0x41,0x12,0x61,0x7b,0xb7,0x22,0xd8,0x15,0x1d,0x70,
        0x9f,0x06,0x5c,0x79,0x07,0x38,0xdb,0x16,0xef,0x70,0x3e,0x59,0x7c,0x09,0x40,0x74,
        0x46,0x63,0x8c,0x58,0xe2,0x57,0xff,0x67,0x55,0x56,0x87,0x1a,0x56,0x22,0x5a,0x2f,
        0xb8,0x16,0x91,0xf3,0x04,0x9e,0x47,0xb7,0xef,0x71,0x39,0xd8,0x30,0xec,0x62,0xaa,
        0x0b,0xeb,0x7e,0xba,0xd0,0x76,0x2a,0x6e,0xed,0xa8,0x7f,0x87,0x16,0xa2,0xda,0x9f,
        0xb4,0x70,0xdc,0xa4,0x1f,0xc5,0x20,0x47,0x5f,0x41,0xf0,0x3e,0x6a,0xdc,0xc4,0x75,
        0xcf,0x11,0x88,0x78,0x98,0x3b,0x4e,0x5e,0xc0,0x25,0x0e,0xe6,0xfc,0xeb,0x0a,0xaa,
        0x22,0x9c,0x39,0xca,0x16,0x80,0x38,0x6a,0xcc,0x91,0x81,0x50,0x16,0x99,0x94,0x0d,
        0x32,0x56,0x6b,0x92,0x92,0x5e,0x52,0xb8,0x6e,0x4b,0x79,0x3f,0x79,0x87,0x21,0xdd,
        0x4e,0xa9,0xf2,0x84,0x7a,0xe9,0xf4,0x3d,0x4e,0xc7,0x46,0x6d,0x3d,0x3c,0x88,0x4e,
        0xa0,0x7d,0xda,0xd8,0x06,0x1a,0x35,0xa5,0x42,0x50,0x5a,0xdf,0x5d,0x43,0x36,0x3e
};

#endif /* MBEDTLS_TEST_DATA_AES_CBC_H */