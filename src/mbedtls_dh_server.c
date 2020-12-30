//
// Created by carlos on 2020/12/29.
//

#include "mbedtls_dh_server.h"
/*
 * Test for rsa hd server
 * 1. init mbedtls, read (DHP) from dh_prime.txt.
 * 2. init network as server.
 * 3. Accept the client network.
 * 4. Generate the server DH public key(SPUK) randomly.
 *    and mod it to gen server DH private key (SPRK)
 *    using the DHP->G&P;
 * 5. Using the RSA private key(1024) sign the SPUK.
 * 6. Send SPUK + signed SPUK hash to client. (SHA256)
 * 7. Recv client DH public key(CPUK)
 * 8. Caculate: SPRK + CPUK = CSK
 * 9. Using the CSK encrypt msg "hello world."
 * 10. Send encrypted msg to Client.
 * */
int mbedtls_dh_server_entry()
{
    int ret = ERROR_NONE;
    int rc = MBEDTLS_EXIT_SUCCESS;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_dhm_context dhm;
    mbedtls_aes_context aes;
    mbedtls_mpi G,P;
    size_t n, buflen;
    uint8_t *pers = "random";
    uint8_t hash[64];
    uint8_t *msg = "hello world!";
    FILE *f = NULL;
    uint8_t *ip = "192.168.3.79";
    uint8_t *port = "5556";
    uint8_t client_ip[255];
    uint8_t buffer[4096] = {'\0'};
    size_t signed_len = 0;
    uint8_t buf2[2];
    int net_len = 0;
    int sig_len = 0;

    mbedtls_dhm_init( &dhm );
    mbedtls_aes_init( &aes );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_mpi_init(&P); mbedtls_mpi_init(&G);

    /*
     * 1a. init mbedtls and read dh_prime.txt
     * */
    mbedtls_printf( "\n  . Seeding the random number generator" );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if((rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                   (const unsigned char *) pers,
                                   strlen( pers ) ) ) != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    /*
     * 1b. read (DHP) from file.
     * */
    if( ( f = fopen( DHM_PRIME_FILE, "rb" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! Could not open dh_prime.txt\n" \
                "  ! Please run dh_genprime first\n\n" );
        ret = -ERROR_COMMON_FILE_OPEN_FAILED;
        goto finish;
    }
    if( (rc = mbedtls_mpi_read_file( &dhm.P, 16, f )) != 0 ||
        (rc = mbedtls_mpi_read_file( &dhm.G, 16, f )) != 0) {
        mbedtls_printf( " failed\n  ! Invalid DH parameter file\n\n" );
        ret = -ERROR_COMMON_FILE_READ_FAILED;
        goto finish;
    }
    fclose(f); f = NULL;
    /* 2a. init network as server */
    rc = utils_net_server_init(ip, port, MBEDTLS_NET_PROTO_TCP);
    if (rc != ERROR_NONE) {
        mbedtls_printf(" failed\n  ! net server init failed\n\n");
        ret = -ERROR_COMMON_NET_INIT_FAILED;
        goto finish;
    }
    /* 2b. accept client. */
    rc = utils_net_server_accept(client_ip, 4096, (char *)buffer);
    if (rc != ERROR_NONE) {
        mbedtls_printf("server accept failed\n");
        ret = -ERROR_COMMON_NET_INIT_FAILED;
        goto finish;
    }
    /* 3a. generate server DH public key SPUK randomly in buffer, len is n */
    mbedtls_printf( "\n  . Sending the server's DH parameters" );
    fflush( stdout );
    memset( buffer, '\0', sizeof( buffer ) );
    rc = mbedtls_dhm_make_params(&dhm, (int)mbedtls_mpi_size(&dhm.P), buffer, &n,
                                 mbedtls_ctr_drbg_random, &ctr_drbg);
    if (rc != 0) {
       mbedtls_printf("dhm make params failed returned %d\n", rc);
       ret = -ERROR_CRYPTO_INIT_FAILED;
       goto finish;
    }
    /* 3b. prepare sign the SPUK */
    sig_len = mbedtls_get_pem_sig_len(PRIVATE_RSA_KEY_FILE, true, NULL);
    if (sig_len < 0) {
        mbedtls_printf("mbedtls_get_pem_sig_len failed!\n");
        ret = -ERROR_CRYPTO_READ_KEY_FAILED;
        goto finish;
    }
    buffer[n    ] = (unsigned char) (sig_len >> 8);
    buffer[n + 1] = (unsigned char) (sig_len);
    ret = mbedtls_rsa_pkcs1_signature(buffer, n, buffer + n + 2, &signed_len,
                                     M_SHA256, PRIVATE_RSA_KEY_FILE, NULL);
    if (ret != 0) {
        mbedtls_printf("rsa_pkcs1_signature failed ret = %d\n", rc);
        goto finish;
    }
    buflen = n + 2 + sig_len;
    buf2[0] = (unsigned char)(buflen >> 8);
    buf2[1] = (unsigned char)(buflen);
    /* 3c. SPUK + signed to buffer */
    mbedtls_printf("send to client len %d n = %d siglen = %d\n", buflen, n, sig_len);
    net_len = utils_net_server_send(buf2, 2);
    if (net_len != 2) {
        mbedtls_printf("net send SPUK failed ret = %d\n", rc);
        ret = -ERROR_COMMON_NET_SEND_FAILED;
        goto finish;
    }
    net_len = utils_net_server_send(buffer, buflen);
    if (net_len != buflen) {
        mbedtls_printf("net send SPUK signed failed ret = %d\n", net_len);
        ret = -ERROR_COMMON_NET_SEND_FAILED;
        goto finish;
    }
    /* 4. get client DH public key CPUK */
    mbedtls_printf( "\n  . Receiving the client's public value" );
    fflush( stdout );
    memset( buffer, '\0', sizeof( buffer ) );
    n = dhm.len;
    net_len = utils_net_server_recv(buffer, n);
    if (net_len != n) {
        mbedtls_printf("\n  . util_net_server_recv failed\n");
        ret = -ERROR_COMMON_NET_RECV_FAILED;
        goto finish;
    }
    rc = mbedtls_dhm_read_public(&dhm, buffer, dhm.len);
    if (rc != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_dhm_read_public returned %d\n\n", ret );
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }

    /* 5. Derive the shared secret CSK -> K = Ys ^ Xc mod P */
    mbedtls_printf( "\n  . Shared secret: " );
    fflush( stdout );
    rc = mbedtls_dhm_calc_secret(&dhm, buffer, sizeof(buffer), &n,
                                 mbedtls_ctr_drbg_random, &ctr_drbg);
    if (rc != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_dhm_calc_secret returned %d\n\n", ret );
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }

    for (n = 0; n < 16; n ++) {
        mbedtls_printf("%02x", buffer[n]);
    }

    /* 6. Encrypt msg using CSK*/
    mbedtls_printf( "...\n  . Encrypting and sending the ciphertext: %s \n", msg);
    fflush( stdout );
    mbedtls_aes_setkey_enc(&aes, buffer, 256);
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, msg, buffer);
    net_len = utils_net_server_send(buffer, 16);
    if (net_len != 16 ) {
        mbedtls_printf("send failed\n");
        goto finish;
    }
    finish:
    utils_net_server_free();
    mbedtls_aes_free( &aes );
    mbedtls_dhm_free( &dhm );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    if (f != NULL)
        fclose(f);
    return ret;
}