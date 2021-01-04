//
// Created by carlos on 2020/12/30.
//
#include "mbedtls_ecdh_client.h"

#define CUR_ID MBEDTLS_ECP_DP_CURVE25519

/*
 * * Be known as: ec ec equation: y^2 = ax^3 + bx + c
 * In the function is behalf by secp256r1 secp384r1
 * * Be known as: shared parameters X in file.
 *
 * Process:
 * 1. Generate the db as private key (PRCK).
 * 2. Caculate Qs = PSK*G = (xa,ya) as PUCK
 * 3. Recv the server public key PUSK.
 * 4. Send PUSK to server.
 * 5. Caculate Ka = PRCK*PUSK = AESKEY.
 * 6. Using AESKEY encrypt msg.
 * 7. Send the encrypted msg to server.
 *
 * P.S : just test ecc, no rsa signed.
 * */
int mbedtls_ecdh_client_entry()
{
    int ret = ERROR_NONE;
    int rc = MBEDTLS_EXIT_SUCCESS;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecdh_context ctx;
    mbedtls_aes_context aes;
    mbedtls_mpi X;
    size_t n, buflen;
    uint8_t *pers = "random";
    uint8_t hash[64];
    uint8_t *msg = "hello world!";
    uint8_t *ip = "192.168.3.79";
    uint8_t *port = "5556";
    uint8_t client_ip[255];
    uint8_t buffer[4096] = {'\0'};
    size_t signed_len = 0;
    uint8_t buf2[2];
    int net_len = 0;
    int sig_len = 0;
    uint8_t *pub_x = NULL;
    size_t pub_len = 0, recv_len = 0;

    mbedtls_ecdh_init(&ctx);
    mbedtls_aes_init(&aes);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_mpi_init(&X);
    /*
     * 0. Initialize
     * */
    mbedtls_printf("Run the gen ecdh share parameter X...\n");
    fflush(stdout);
    rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char*)pers, strlen(pers));
    if (rc != 0) {
        mbedtls_printf("  . Failed, mbedtls_ctr_drbg_seed, returned %d, line %d\n",
                       rc, __LINE__);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    mbedtls_printf("  . init: random initialize finish.\n");
    ret = utils_net_client_init(ip, port, MBEDTLS_NET_PROTO_TCP);
    if (ret != ERROR_NONE) {
        goto finish;
    }
    /*
     * 1. Generate keypair:
     * * private key -> ctx.d;
     * * public key  -> ctx.Q; ctx.Q.x Q.y Q.z;
     *
     * */
    rc = mbedtls_ecp_group_load(&ctx.grp, CUR_ID);
    if (rc != 0) {
        mbedtls_printf("  . Failed, ecp_group_load, returned %d, line %d\n",
                       rc, __LINE__);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    pub_len = ctx.grp.pbits/8;
    pub_x = (uint8_t*)malloc(pub_len);
    if (pub_x == NULL) {
        ret = -ERROR_COMMON_MALLOC_FAILED;
        mbedtls_printf("  . Failed, pub_x malloc space, returned NULL, line %d\n",
                       __LINE__);
        goto finish;
    }
    mbedtls_printf("  . init: load ecp group.\n");
    /* 2. recv PUSK from server */
    net_len = utils_net_client_recv(buf2, 2);
    if (net_len != 2) {
        mbedtls_printf("  . Failed, net recv buffer length, returned len %d, line %d\n",
                       net_len, __LINE__);
        ret = -ERROR_COMMON_NET_SEND_FAILED;
        goto finish;
    }
    recv_len = (size_t)(((uint16_t)buf2[0]) << 8) & 0xFF00 | ((uint16_t)buf2[1] & 0x00FF);
    if (recv_len != pub_len) {
        mbedtls_printf("  . Failed, recv_len not match cur_len, returned len recv_len %ld, line %d\n",
                       recv_len, __LINE__);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    net_len = utils_net_client_recv(pub_x, pub_len);
    if (net_len != pub_len) {
        mbedtls_printf("  . Failed, recv failed, returned len %d, line %d\n",
                       net_len, __LINE__);
        ret = -ERROR_COMMON_NET_RECV_FAILED;
        goto finish;
    }
    mbedtls_printf("  . Recved PUSK..\n");

    rc = mbedtls_ecdh_gen_public(&ctx.grp, &ctx.d, &ctx.Q,
                                 mbedtls_ctr_drbg_random, &ctr_drbg);
    if (rc != 0) {
        mbedtls_printf("  . Failed, ecdh_gen_public, returned %d, line %d\n",
                       rc, __LINE__);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    mbedtls_printf("  . init: ecdh genned public\n");
    /* 1.1 write public key to */
    rc = mbedtls_mpi_write_binary(&ctx.Q.X, pub_x, pub_len);
    if (rc != 0) {
        mbedtls_printf("  . Failed, mpi write binary, returned %d, line %d\n",
                       rc, __LINE__);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
   /* 2. send PUCK to client. */
    buf2[0] = (pub_len) & 0xFF;
    buf2[1] = (pub_len) >> 8 & 0xFF;
    if (net_len != pub_len) {
        mbedtls_printf("  . Failed, net send buffer length, returned len %d, line %d\n",
                       net_len, __LINE__);
        ret = -ERROR_COMMON_NET_SEND_FAILED;
        goto finish;
    }
    net_len = utils_net_client_send(pub_x, pub_len);
    if (net_len != pub_len) {
        mbedtls_printf("  . Failed, net send public key, returned len %d, line %d\n",
                       net_len, __LINE__);
        ret = -ERROR_COMMON_NET_SEND_FAILED;
        goto finish;
    }

    /* 4. Caculate key */
    rc = mbedtls_mpi_lset(&ctx.Qp.Z, 1);
    if (rc != 0) {
        mbedtls_printf("  . Failed, mpi_lset, returned %d, line %d\n", rc, __LINE__);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }

    /* 5. Read mpi binary. */
    rc = mbedtls_mpi_read_binary(&ctx.Qp.X, pub_x, pub_len);
    if (rc != 0) {
        mbedtls_printf("  . Failed, mpi read binary, returned %d, line %d\n",
                       rc, __LINE__);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }

    /* 6. Caculate the Key */
    rc = mbedtls_ecdh_compute_shared(&ctx.grp, &ctx.z,
                                     &ctx.Qp, &ctx.d,
                                     mbedtls_ctr_drbg_random, &ctr_drbg);
    if (rc != 0) {
        mbedtls_printf("  . Failed, ecdh compute shared, returned %d, line %d\n",
                       rc, __LINE__);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }

    /* 7. write key. */
    memset(pub_x, 0, pub_len);
    rc = mbedtls_mpi_write_binary(&ctx.z, pub_x, pub_len);
    if (rc != 0) {
        mbedtls_printf("  . Failed, mpi write binary, returned %d, line %d\n",
                       rc, __LINE__);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }

    /* 8. encryt msg */
    mbedtls_printf( "...\n  . Encrypting and sending the ciphertext: %s \n", msg);
    fflush( stdout );
    mbedtls_aes_setkey_dec(&aes, pub_x, pub_len);
    net_len = utils_net_client_recv(buffer, 16);
    if (net_len != 16 ) {
        mbedtls_printf("  . Failed, recv failed, returned len %d, line %d\n",
                       net_len, __LINE__);
        ret = -ERROR_COMMON_NET_RECV_FAILED;
        goto finish;
    }
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, msg, buffer);
    finish:
    mbedtls_ecdh_free(&ctx);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    if (pub_x != NULL)
        free(pub_x);
    utils_net_client_free();
    return ret;
}
