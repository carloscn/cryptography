#include <stdio.h>
#include <string.h>
#include "aes.h"
#include "aes_cipher.h"


#if defined(ECB) && (ECB == 1)

int32_t aes_init_ctx(struct aes_ctx* ctx)
{
    (void)(ctx);
    return 0;
}

void aes_free(struct aes_ctx* ctx)
{
    (void)(ctx);
}

#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
int32_t aes_ctx_set_key(struct aes_ctx* ctx, const uint8_t* key, size_t key_len)
{
    int32_t ret = 0;

    if (NULL == ctx || NULL == key) {
        printf("[error] : ctx or key pointer is NULL\n");
        ret = -1;
        goto finish;
    }

    if (128 != key_len && 192 != key_len && 256 != key_len) {
        printf("[error] : invalid key len = %zd\n", key_len);
        ret = -1;
        goto finish;
    }

    aes_key_expansion(ctx->round_key, key, key_len);

finish:
    return ret;
}

int32_t aes_ctx_set_iv(struct aes_ctx* ctx, const uint8_t* iv)
{
    int32_t ret = 0;

    if (NULL == ctx || NULL == iv) {
        printf("[error] : ctx or iv pointer is NULL\n");
        ret = -1;
        goto finish;
    }

    memcpy(ctx->iv, iv, AES_BLOCKLEN);

finish:
    return ret;

}
#endif

int32_t aes_enc_ecb(const struct aes_ctx* ctx, uint8_t* buf, size_t buf_len)
{
    int32_t ret = 0;

    if (0 == buf_len) {
        goto finish;
    }

    if (NULL == ctx || NULL == buf) {
        printf("[error] : ctx or buf pointer is NULL\n");
        ret = -1;
        goto finish;
    }

    aes((state_t*)buf, ctx->round_key);

finish:
    return ret;
}

int32_t aes_dec_ecb(const struct aes_ctx* ctx, uint8_t* buf, size_t buf_len)
{
    int32_t ret = 0;

    if (0 == buf_len) {
        goto finish;
    }

    if (NULL == ctx || NULL == buf) {
        printf("[error] : ctx or buf pointer is NULL\n");
        ret = -1;
        goto finish;
    }

    aes_inv((state_t*)buf, ctx->round_key);

finish:
    return ret;
}


#endif // #if defined(ECB) && (ECB == 1)

#if defined(CBC) && (CBC == 1)

static void xor_with_iv(uint8_t* buf, const uint8_t* iv)
{
    uint8_t i;

    // The block in AES is always 128bit no matter the key size
    for (i = 0; i < AES_BLOCKLEN; ++i) {
        buf[i] ^= iv[i];
    }
}

int32_t aes_enc_cbc(struct aes_ctx* ctx, uint8_t* buf, size_t buf_len)
{
    int32_t ret = 0;
    size_t i;
    uint8_t *iv = NULL;

    if (0 == buf_len) {
        goto finish;
    }

    if (NULL == ctx || NULL == buf) {
        printf("[error] : ctx or buf pointer is NULL\n");
        ret = -1;
        goto finish;
    }

    iv = ctx->iv;
    for (i = 0; i < buf_len; i += AES_BLOCKLEN) {
        xor_with_iv(buf, iv);
        aes((state_t*)buf, ctx->round_key);
        iv = buf;
        buf += AES_BLOCKLEN;
    }

    /* store Iv in ctx for next call */
    memcpy(ctx->iv, iv, AES_BLOCKLEN);

finish:
    return ret;
}

int32_t aes_dec_cbc(struct aes_ctx* ctx, uint8_t* buf, size_t buf_len)
{
    int32_t ret = 0;
    size_t i;
    uint8_t *iv = NULL;
    uint8_t store_next_iv[AES_BLOCKLEN] = {0};

    if (0 == buf_len) {
        goto finish;
    }

    if (NULL == ctx || NULL == buf) {
        printf("[error] : ctx or buf pointer is NULL\n");
        ret = -1;
        goto finish;
    }

    for (i = 0; i < buf_len; i += AES_BLOCKLEN) {
        memcpy(store_next_iv, buf, AES_BLOCKLEN);
        aes_inv((state_t*)buf, ctx->round_key);
        xor_with_iv(buf, ctx->iv);
        memcpy(ctx->iv, store_next_iv, AES_BLOCKLEN);
        buf += AES_BLOCKLEN;
    }

finish:
    return ret;
}



#endif // #if defined(CBC) && (CBC == 1)