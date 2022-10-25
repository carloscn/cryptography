#ifndef _AES_H
#define _AES_H

#include <stdint.h>
#include <stddef.h>

typedef uint8_t state_t[4][4];

void aes(state_t* state, const uint8_t* round_key);
void aes_inv(state_t* state, const uint8_t* round_key);
void aes_key_expansion(uint8_t* round_key, const uint8_t* key, size_t key_len);

#endif /* _AES_H */