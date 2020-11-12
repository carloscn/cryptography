/*
 ============================================================================
 Name        : openssl_warm.c
 Author      :
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include "unit_test.h"

int main(void)
{
    int ret = 0;
//	printf("--------------------------\nmain: test_md5...\n--------------------------\n");
//	test_md5();
//	printf("--------------------------\nmain: test_evp_md5...\n--------------------------\n");
//	test_evp_md5();
//	printf("--------------------------\nmain: gen key pairs...\n--------------------------\n");
//    ret = openssl_gen_rsa_pkcs8_pem_files(PUBLIC_RSA_KEY_FILE, PRIVATE_RSA_KEY_FILE, NULL, 0, 512);
    ret = openssl_gen_rsa_pkcs1_pem_files(PUBLIC_RSA_KEY_FILE, PRIVATE_RSA_KEY_FILE, NULL, 0, 512);
//    assert(ret == 0);
//    printf("mbedtls generate the rsa pem keys\n");
//    mbedtls_gen_rsa_pem_key_files(PUBLIC_RSA_KEY_FILE, PRIVATE_RSA_KEY_FILE, NULL, 0, 512);
	//printf("--------------------------\nmain: rsa encrypt using the public key and decrypt using the private key...\n--------------------------\n");
//	ret = test_evp_rsa_encrypt_decrypt();
//	assert(ret == 0);
//	printf("--------------------------\nmain: rsa signature verify...\n--------------------------\n");
//	ret = test_evp_rsa_signature_verify();
//	printf("--------------------------\nmain: gen sm2 key pairs...\n--------------------------\n");
//	generate_sm2_key_files(PUBLIC_SM2_KEY_FILE, PRIVATE_SM2_KEY_FILE,NULL, 0);
//	printf("--------------------------\nmain: sm2 encrypt using the public key and decrypt using the private key...\n--------------------------\n");
//	test_evp_sm2_encrypt_decrypt();
//	printf("--------------------------\nmain: rsa signature verify...\n--------------------------\n");
//	test_evp_sm2_signature_verify();
//	printf("----------------------\nmain:test mbedtls rsa enc dec...\n-----------------------\n");
//    test_mbedtls_ecc_enc_dec();
//    mbedtls_test_ecc_sign_verfiy();
    mbedtls_test_rsa_sign_verify();
//	printf("--------------------------\nmain: test end \n--------------------------\n");
//    printf("--------------------------\nmain: test_evp_md5...\n--------------------------\n");
//    test_evp_md5();
//    printf("--------------------------\nmain: test_mbedtls_md5...\n--------------------------\n");
//    test_mbedtls_md5();

}
