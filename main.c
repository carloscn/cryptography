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
#include "test_case.h"

int main(void)
{
	printf("--------------------------\nmain: test_md5...\n--------------------------\n");
	test_md5();
	printf("--------------------------\nmain: test_evp_md5...\n--------------------------\n");
	test_evp_md5();
	printf("--------------------------\nmain: gen key pairs...\n--------------------------\n");
	generate_rsa_key_files(PUBLIC_RSA_KEY_FILE, PRIVATE_RSA_KEY_FILE, "12345", 5);
	printf("--------------------------\nmain: rsa encrypt using the public key and decrypt using the private key...\n--------------------------\n");
	test_evp_rsa_encrypt_decrypt();
	printf("--------------------------\nmain: rsa signature verify...\n--------------------------\n");
	test_evp_rsa_signature_verify();
	printf("--------------------------\nmain: gen sm2 key pairs...\n--------------------------\n");
	generate_sm2_key_files(PUBLIC_SM2_KEY_FILE, PRIVATE_SM2_KEY_FILE,"12345", 5);
	printf("--------------------------\nmain: sm2 encrypt using the public key and decrypt using the private key...\n--------------------------\n");
	test_evp_sm2_encrypt_decrypt();
	printf("--------------------------\nmain: rsa signature verify...\n--------------------------\n");
	test_evp_sm2_signature_verify();
	printf("--------------------------\nmain: test end \n--------------------------\n");
}
