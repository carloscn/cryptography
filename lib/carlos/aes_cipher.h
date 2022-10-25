#ifndef _AES_CIPHER_H
#define _AES_CIPHER_H

#include <stdint.h>

// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES encryption in CBC-mode of operation.
// CTR enables encryption in counter-mode.
// ECB enables the basic ECB 16-byte block algorithm. All can be enabled simultaneously.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.
#ifndef CBC
  #define CBC 1
#endif

#ifndef ECB
  #define ECB 1
#endif

#ifndef CTR
  #define CTR 1
#endif

#define AES128 1
//#define AES192 1
//#define AES256 1

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only

#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16   // Key length in bytes
    #define AES_keyExpSize 176
#endif

struct aes_ctx
{
  uint8_t round_key[AES_keyExpSize];
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
  uint8_t iv[AES_BLOCKLEN];
#endif
};

int32_t aes_init_ctx(struct aes_ctx* ctx);
int32_t aes_ctx_set_key(struct aes_ctx* ctx, const uint8_t* key, size_t key_len);
int32_t aes_ctx_set_iv(struct aes_ctx* ctx, const uint8_t* iv);
void aes_free_ctx(struct aes_ctx* ctx);

#if defined(ECB) && (ECB == 1)
// buffer size is exactly AES_BLOCKLEN bytes;
// you need only AES_init_ctx as IV is not used in ECB
// NB: ECB is considered insecure for most uses
int32_t aes_dec_ecb(const struct aes_ctx* ctx, uint8_t* buf, size_t buf_len);
int32_t aes_enc_ecb(const struct aes_ctx* ctx, uint8_t* buf, size_t buf_len);

#endif // #if defined(ECB) && (ECB == !)


#if defined(CBC) && (CBC == 1)
// buffer size MUST be mutile of AES_BLOCKLEN;
// Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key
int32_t aes_enc_cbc(struct aes_ctx* ctx, uint8_t* buf, size_t buf_len);
int32_t aes_dec_cbc(struct aes_ctx* ctx, uint8_t* buf, size_t buf_len);

#endif // #if defined(CBC) && (CBC == 1)

#if defined(CTR) && (CTR == 1)

// Same function for encrypting as for decrypting.
// IV is incremented for every block, and used after encryption as XOR-compliment for output
// Suggesting https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx with AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key
int32_t aes_enc_ctr(struct aes_ctx* ctx, uint8_t* buf, size_t length);
int32_t aes_dec_ctr(struct aes_ctx* ctx, uint8_t* buf, size_t length);

#endif // #if defined(CTR) && (CTR == 1)

#endif /* _AES_H */