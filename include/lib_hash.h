#ifndef LIB_HASH_H
#define LIB_HASH_H

#include "c_types.h"

typedef struct {
    uint32 state[8];
    uint64 bitlen;
    uint8  data[64];
    uint8  datalen;
} SHA256_Ctx;

void SHA256_Init(SHA256_Ctx* ctx);
void SHA256_Write(SHA256_Ctx* ctx, void* data, uint len);
void SHA256_Sum(SHA256_Ctx* ctx, byte (*hash)[32]);

#endif // LIB_HASH_H
