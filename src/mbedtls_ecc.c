//
// Created by carlos on 2020/11/12.
//

#include "mbedtls_ecc.h"

int mbedtls_ecc_encrypt(unsigned char *plain_text, size_t plain_len,
                        unsigned char *cipher_text, size_t *cipher_len,
                        unsigned char *pem_file)
{

}

int mbedtls_ecc_decryt(unsigned char *cipher_text, size_t cipher_len,
                       unsigned char *plain_text, size_t *plain_len,
                       const unsigned char *pem_file, const unsigned char *passwd)
{

}

int mbedtls_ecdsa_signature(unsigned char *sign_rom, size_t sign_rom_len,
                            unsigned char *result, size_t *result_len,
                            const unsigned char *priv_pem_file, const unsigned char *passwd)
{

}

int mbedtls_ecdsa_verified(unsigned char *sign_rom, size_t sign_rom_len,
                           unsigned char *result, size_t result_len,
                           const unsigned char *pub_pem_file)

{

}
