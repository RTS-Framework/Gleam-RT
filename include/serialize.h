#ifndef SERIALIZE_H
#define SERIALIZE_H

#include "c_types.h"

// serialized data structure
// +---------+----------+----------+----------+------------+
// |  magic  |  item 1  |  item 2  | item END |  raw data  |
// +---------+----------+----------+----------+------------+
// |  uint32 |  uint32  |  uint32  |  uint32  |    var     |
// +---------+----------+----------+----------+------------+
//
// item data structure
// 0······· value or pointer
// ·0000000 data length

#define SERIALIZE_MAGIC        0xACFFFFEE
#define SERIALIZE_ITEM_END     0x00000000

#define SERIALIZE_MASK_TYPE    0x80000000
#define SERIALIZE_MASK_LENGTH  0x7FFFFFFF

#define SERIALIZE_TYPE_VALUE   0x00000000
#define SERIALIZE_TYPE_POINTER 0x80000000

// Serialize is used to serialize structure to a buffer.
// If success, return the serialized data length. If failed, return 0.
// If serialized is NULL, it will calculate the serialized data length.
uint32 Serialize(uint32* descriptor, void* data, void* serialized);

// Unserialize is used to unserialize data to a structure.
BOOL Unserialize(void* serialized, void* data);

#endif // SERIALIZE_H
