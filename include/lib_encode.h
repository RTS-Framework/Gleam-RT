#ifndef LIB_ENCODE_H
#define LIB_ENCODE_H

#include "c_types.h"

// methods about hex encoding.
// if dst is NULL, it only calculate the output length.
// it will return -1 when call Decode with invalid data.
uint Hex_Encode(void* src, uint len, byte* dst);
uint Hex_Decode(byte* src, uint len, void* dst);

// methods about base64 encoding.
// if dst is NULL, it only calculate the output length.
// it will return -1 when call Decode with invalid data.
uint Base64_Encode(void* src, uint len, byte* dst);
uint Base64_Decode(byte* src, uint len, void* dst);

#endif // LIB_ENCODE_H
