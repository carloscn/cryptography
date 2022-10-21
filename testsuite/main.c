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
#include "Basic.h"
#include "test_kasumi.h"
#include "unit_test_mbedtls.h"
#include "unit_test_gmssl.h"

int main(int argc, char* argv[] ) {
    CU_BasicRunMode mode = CU_BRM_VERBOSE;
    CU_ErrorAction error_action = CUEA_IGNORE;

    int i;
    setvbuf(stdout, NULL, _IONBF, 1);

    for (i=2 ; i<argc ; i++) {
        if (!strcmp("-i", argv[i])) {
            error_action = CUEA_IGNORE;
        }
        else if (!strcmp("-f", argv[i])) {
            error_action = CUEA_FAIL;
        }
        else if (!strcmp("-A", argv[i])) {
            error_action = CUEA_ABORT;
        }
        else if (!strcmp("-s", argv[i])) {
            mode = CU_BRM_SILENT;
        }
        else if (!strcmp("-n", argv[i])) {
            mode = CU_BRM_NORMAL;
        }
        else if (!strcmp("-v", argv[i])) {
            mode = CU_BRM_VERBOSE;
        }
        else if (!strcmp("-e", argv[i])) {
            return 1;
        }
        else {
            printf("\nUsage:  BasicTest [options]\n\n"
                   "Options:   -i   ignore framework errors [default].\n"
                   "           -f   fail on framework error.\n"
                   "           -A   abort on framework error.\n\n"
                   "           -s   silent mode - no output to screen.\n"
                   "           -n   normal mode - standard output to screen.\n"
                   "           -v   verbose mode - max output to screen [default].\n\n"
                   "           -e   print expected test results and exit.\n"
                   "           -h   print this message and exit.\n\n");
            return 1;
        }
    }
    if (CU_initialize_registry()) {
        printf("\nInitialization of Test Registry failed.");
    }
    else {
        add_mbedtls_testsuite();
        //add_gmssl_testsuite();
        //add_openssl_testsuite();
        CU_basic_set_mode(mode);
        CU_set_error_action(error_action);
        printf("\nTests completed with return value %d.\n", CU_basic_run_tests());
        CU_cleanup_registry();
    }

    return 1;
}

int s_main(void)
{
    int ret = 0;
//	printf("--------------------------\nmain: test_md5...\n--------------------------\n");
//	test_md5();
//	printf("--------------------------\nmain: test_evp_md5...\n--------------------------\n");
//	test_evp_md5();
//	ret = test_evp_pkcs1_rsa_encrypt_decrypt();
//	assert(ret == 0);
//    ret = test_evp_pkcs8_rsa_encrypt_decrypt();
//	assert(ret == 0);
//	printf("--------------------------\nmain: rsa signature verify...\n--------------------------\n");
//	ret = test_evp_pkcs1_rsa_signature_verify();
//    ret = test_evp_pkcs8_rsa_signature_verify();
//	printf("--------------------------\nmain: gen sm2 key pairs...\n--------------------------\n");
//	generate_sm2_key_files(PUBLIC_SM2_KEY_FILE, PRIVATE_SM2_KEY_FILE,NULL, 0);
//	printf("--------------------------\nmain: sm2 encrypt using the public key and decrypt using the private key...\n--------------------------\n");
//	test_evp_sm2_encrypt_decrypt();
//	printf("--------------------------\nmain: rsa signature verify...\n--------------------------\n");
//	test_evp_sm2_signature_verify();
//	printf("----------------------\nmain:test mbedtls rsa enc dec...\n-----------------------\n");
//    test_mbedtls_ecc_enc_dec();
//    mbedtls_test_ecc_sign_verfiy();
//    mbedtls_test_rsa_sign_verify();
//	printf("--------------------------\nmain: test end \n--------------------------\n");
//    printf("--------------------------\nmain: test_evp_md5...\n--------------------------\n");
//    test_evp_md5();
//    printf("--------------------------\nmain: test_mbedtls_md5...\n--------------------------\n");
//    test_mbedtls_md5();
//    test_mbedtls_rsa_encrypt_decrypt();
    //mbedtls_test_ecc_sign_verfiy();
//    test_evp_ecc_signature_verify();
//    mbedtls_test_ecdsa_sign_verfiy();
//    test_evp_ecdsa_signature_verify();
//    test_mbedtls_random();
//    test_tcp_server();
//    test_tcp_client();
//        test_gen_dhm();
//      test_rsa_dh_server();
//      test_rsa_dh_client();
//    test_gen_ecdhm();
//    test_ecdh_server();
//    test_ecdh_client();
//    test_cert_req();
//    test_cert_crt();
//    test_sca();
//    test_kasumi_entry();
}
