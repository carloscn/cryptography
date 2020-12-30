//
// Created by carlos on 2020/12/28.
//

#include "utils_net_client.h"

static mbedtls_net_context client_net_ctx;

int utils_net_client_free()
{
    mbedtls_net_free(&client_net_ctx);
}

// proto: MBEDTLS_NET_PROTO_TCP or MBEDTLS_NET_PROTO_UDP
int utils_net_client_init(const char *bind_ip, const char *port, int proto)
{
    int rc = MBEDTLS_EXIT_SUCCESS, ret = ERROR_NONE;
    if (bind_ip == NULL || port == NULL) {
        mbedtls_printf("input parameter error\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    if (proto != MBEDTLS_NET_PROTO_TCP &&
        proto != MBEDTLS_NET_PROTO_UDP) {
        mbedtls_printf("input paramerter error protocal\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    mbedtls_net_init(&client_net_ctx);
    rc = mbedtls_net_connect(&client_net_ctx, bind_ip, port, proto);
    if (rc != 0) {
        mbedtls_printf("error net connect error ret = %d\n", rc);
        ret = -ERROR_COMMON_NET_INIT_FAILED;
        goto finish;
    }
    mbedtls_printf("net client link %s port %s successful.", bind_ip, port);
    if (proto == MBEDTLS_NET_PROTO_UDP)
        mbedtls_printf(" as UDP client.\n");
    else if (proto == MBEDTLS_NET_PROTO_TCP)
        mbedtls_printf(" as TCP client.\n");
    finish:
    if (ret != ERROR_NONE)
        utils_net_client_free();
    return ret;
}

int utils_net_client_send(const unsigned char *buf, size_t len)
{
    int rc = MBEDTLS_EXIT_SUCCESS;
    if (buf == NULL || len == 0) {
        mbedtls_printf("send error ,input buf or len is NULL or 0\n");
        rc = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    rc  = mbedtls_net_send(&client_net_ctx, buf, len);
    if (rc < 0) {
        mbedtls_printf("net send failed, ret = %d\n", rc);
        rc = -ERROR_COMMON_NET_SEND_FAILED;
        goto finish;
    }
    finish:
    return rc;
}

int utils_net_client_recv(unsigned char* buf, size_t max_len)
{
    int rc = 0;
    if (buf == NULL || max_len == 0) {
        mbedtls_printf("recv error ,input buf or len is NULL or 0\n");
        rc = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    memset(buf, '\0', max_len);
    rc = mbedtls_net_recv(&client_net_ctx, buf, max_len);
    if (rc <= 0) {
        mbedtls_printf("net recv failed, ret = %ld\n", rc);
        rc = -ERROR_COMMON_NET_RECV_FAILED;
        goto finish;
    }
    finish:
    return rc;
}

int utils_net_client_recv_timeout(unsigned char* buf, size_t max_len, uint32_t timeout)
{
    int rc = 0;
    if (buf == NULL || max_len == 0) {
        mbedtls_printf("recv error ,input buf or len is NULL or 0\n");
        rc = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    memset(buf, '\0', max_len);
    rc = mbedtls_net_recv_timeout(&client_net_ctx, buf, max_len, timeout);
    if (rc <= 0) {
        mbedtls_printf("net recv failed, ret = %ld\n", rc);
        rc = -ERROR_COMMON_NET_RECV_FAILED;
        goto finish;
    }
    finish:
    return rc;
}