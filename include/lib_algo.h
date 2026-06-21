#ifndef LIB_ALGO_H
#define LIB_ALGO_H

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

uint Hex_Encode(void* src, uint len, byte* dst);
uint Hex_Decode(byte* src, uint len, void* dst);

#endif // LIB_ALGO_H
