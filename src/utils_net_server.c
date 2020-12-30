//
// Created by carlos on 2020/12/28.
//

/*
 * This instance is tcp un-security channel for transmitting the data.
 * In order to be lazy, we use the net interface derived from mbedtls.
 * The OpenSSL example also relies on this net interface.
 *
 * */
#include "utils_net_client.h"

static mbedtls_net_context server_ctx;
static mbedtls_net_context client_ctx;

int utils_net_server_free()
{
    mbedtls_net_free(&server_ctx);
    mbedtls_net_free(&client_ctx);
}
// proto: MBEDTLS_NET_PROTO_TCP or MBEDTLS_NET_PROTO_UDP
int utils_net_server_init(const char *bind_ip, const char *port, int proto)
{
    int rc = MBEDTLS_EXIT_SUCCESS, ret = ERROR_NONE;
    if (bind_ip == NULL || port == NULL) {
        mbedtls_printf("input parameter error\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    if ((proto != (int)MBEDTLS_NET_PROTO_TCP) &&
        (proto != (int)MBEDTLS_NET_PROTO_UDP)) {
        mbedtls_printf("input paramerter error protocal %d\n", proto);
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    mbedtls_net_init(&server_ctx);
    mbedtls_net_init(&client_ctx);
    rc = mbedtls_net_bind(&server_ctx, bind_ip, port, proto);
    if (rc != 0) {
        mbedtls_printf("error net bind error ret = %d\n", rc);
        ret = -ERROR_COMMON_NET_INIT_FAILED;
        goto finish;
    }
    mbedtls_printf("net server blind %s port %s successful.", bind_ip, port);
    if (proto == MBEDTLS_NET_PROTO_UDP)
        mbedtls_printf(" as UDP server.\n");
    else if (proto == MBEDTLS_NET_PROTO_TCP)
        mbedtls_printf(" as TCP server.\n");
    finish:
    if (ret != ERROR_NONE) {
        utils_net_server_free();
    }
    return ret;
}

int utils_net_server_accept(void *client_ip, size_t buf_size, size_t *ip_len)
{
    int ret = ERROR_NONE, rc = MBEDTLS_EXIT_SUCCESS;
    if (client_ip == NULL || ip_len == NULL) {
        mbedtls_printf("net accept failed, input error\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    rc = mbedtls_net_accept(&server_ctx, &client_ctx, (void*)client_ip, buf_size, ip_len);
    if (rc != 0) {
        mbedtls_printf("net accept failed, ret = %d\n", rc);
        ret = -ERROR_COMMON_NET_RECV_FAILED;
        goto finish;
    }

    finish:
    return ret;
}

int utils_net_server_send(const unsigned char *buf, size_t len)
{
    int ret = ERROR_NONE;
    if (buf == NULL || len == 0) {
        mbedtls_printf("send error ,input buf or len is NULL or 0\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    ret = mbedtls_net_send(&client_ctx, buf, len);
    if (ret < 0) {
        mbedtls_printf("net send failed, ret = %ld\n", ret);
        ret = -ERROR_COMMON_NET_SEND_FAILED;
        goto finish;
    }
    finish:
    return ret;
}

int utils_net_server_recv(unsigned char* buf, size_t max_len)
{
    int rc = 0;
    if (buf == NULL || max_len == 0) {
        mbedtls_printf("recv error ,input buf or len is NULL or 0\n");
        rc = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    memset(buf, '\0', max_len);
    rc = mbedtls_net_recv(&client_ctx, buf, max_len);
    if (rc < 0) {
        mbedtls_printf("  . net recv failed, ret = %d\n", rc);
        rc = -ERROR_COMMON_NET_RECV_FAILED;
        goto finish;
    }
    finish:
    return rc;
}
int utils_net_server_recv_timeout(unsigned char* buf, size_t max_len, uint32_t timeout)
{
    int rc = 0;
    if (buf == NULL || max_len == 0) {
        mbedtls_printf("recv error ,input buf or len is NULL or 0\n");
        rc = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    memset(buf, '\0', max_len);
    rc = mbedtls_net_recv_timeout(&client_ctx, buf, max_len, timeout);
    if (rc < 0) {
        mbedtls_printf("net recv failed, ret = %d\n", rc);
        rc = -ERROR_COMMON_NET_RECV_FAILED;
        goto finish;
    }
    finish:
    return rc;
}