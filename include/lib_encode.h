#ifndef LIB_ENCODE_H
#define LIB_ENCODE_H

#include "c_types.h"

uint Hex_Encode(void* src, uint len, byte* dst);
uint Hex_Decode(byte* src, uint len, void* dst);

#endif // LIB_ENCODE_H
