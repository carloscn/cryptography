//
// Created by carlos on 2020/12/29.
//

#include "mbedtls_dh_client.h"

/*
 * Test for rsa hd client.
 * 1. init mbedtls, read (DHP) from dh_prime.txt
 * 2. init network as client.
 * 3. Connect to server network.
 * 4. Recv server's SPUK and signed SPUK hash. (SHA256)
 * 5. Do SPUK hash, and using the public key to verify the SPUK. (RSA1024)
 * 6. Generate the client DH public key(CPUK) randomly.
 *    and mod it to gen client DH private key (CPRK)
 *    using the DHP
 * 7. Send CPUK to server.
 * 8. Caculate: SPUK + CPRK = CSK.
 * 9. Recv the server encrypted msg.
 * 10. Decrypt the msg as "hello world."
 * */
int mbedtls_dh_client_entry()
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
    FILE *f = NULL;
    uint8_t *ip = "192.168.3.79";
    uint8_t *port = "5556";
    uint8_t buffer[4096] = {'\0'};
    size_t signed_len = 0;
    int net_len = 0;
    uint8_t  *p = NULL, *end = NULL;
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
    /* 2a. init network as client */
    rc = utils_net_client_init(ip, port, MBEDTLS_NET_PROTO_TCP);
    if (rc != ERROR_NONE) {
        mbedtls_printf(" failed\n  ! net client init failed\n\n");
        ret = -ERROR_COMMON_NET_INIT_FAILED;
        goto finish;
    }
    /* 3a. recv the SPUK from net server*/
    /* 3a.1 get len*/
    memset(buffer, '\0', sizeof(buffer));
    net_len = utils_net_client_recv(buffer, 2);
    if (net_len != 2) {
        goto finish;
    }
    n = buflen = (buffer[0] << 8) | buffer[1];
    if (buflen < 1 || buflen > sizeof(buffer)) {
        mbedtls_printf( " failed\n  ! Got an invalid buffer length\n\n" );
        ret = -ERROR_COMMON_BUFFER_INSUFFIENT;
        goto finish;
    }
    mbedtls_printf("recv buffer len is %d\n", n);
    /* 3a.2 get SPUK from net server*/
    memset(buffer, '\0', sizeof(buffer));
    net_len = utils_net_client_recv(buffer, n);
    if (net_len != (int)n) {
        mbedtls_printf( " failed\n  ! mbedtls_net_recv returned %d\n\n", ret );
        ret = -ERROR_COMMON_NET_RECV_FAILED;
        goto finish;
    }
    p = buffer;
    end = buffer + buflen;
    rc = mbedtls_dhm_read_params(&dhm, &p, end);
    if (rc != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_dhm_read_params returned 0x%2X\n\n", rc );
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    if (dhm.len < 64 || dhm.len > 512) {
        mbedtls_printf( " failed\n  ! Invalid DHM modulus size\n\n" );
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    /* 4. verify */
    mbedtls_printf( "\n  . Verifying the server's RSA signature" );
    fflush( stdout );
    p += 2;
    sig_len = mbedtls_get_pem_sig_len(PUBLIC_RSA_KEY_FILE, false, NULL);
    if( ( n = (size_t) ( end - p ) ) != sig_len)
    {
        mbedtls_printf( " failed\n  ! Invalid RSA signature size, %ld != %d \n\n", n,  sig_len);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    mbedtls_printf( " \n RSA signature size, %ld == %d \n\n", n,  sig_len);
    signed_len = (size_t)(p-2-buffer);
    ret = mbedtls_rsa_pkcs1_verified(p, n,
                                     buffer, signed_len,
                                     M_SHA256, PUBLIC_RSA_KEY_FILE);
    if (ret != 0) {
        printf("RSA verified failed\n");
        goto finish;
    }
    /* 5. Send client public key CPUK to server */
    n = dhm.len;
    rc = mbedtls_dhm_make_public(&dhm, (int)dhm.len, buffer, n,
                                 mbedtls_ctr_drbg_random, &ctr_drbg);
    if (rc != 0) {
        mbedtls_printf( " failed\n  ! mbedtls_dhm_read_public returned %d\n\n", rc );
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    net_len = utils_net_client_send(buffer, n);
    if (net_len != n) {
        mbedtls_printf( " failed\n  ! mbedtls_net_send returned %d\n\n", ret );
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
    /* 6. Decrypt msg using CSK*/
    mbedtls_printf( "...\n  . Decrypting and recv the ciphertext" );
    fflush( stdout );
    mbedtls_aes_setkey_dec(&aes, buffer, 256);
    net_len = utils_net_client_recv(buffer, 16);
    if (net_len != 16) {
        mbedtls_printf("recv failed!\n");
        goto finish;
    }
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, buffer, buffer);
    buffer[16] = '\0';
    mbedtls_printf( "\n  . Plaintext is \"%s\"\n\n", (char *) buffer );
finish:
    utils_net_client_free();
    mbedtls_aes_free( &aes );
    mbedtls_dhm_free( &dhm );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    if (f != NULL)
        fclose(f);
    return ret;
}
