#ifndef CRYPTO_H
#define CRYPTO_H

#include "c_types.h"

#define CRYPTO_KEY_SIZE 32
#define CRYPTO_IV_SIZE  16

// EncryptBuffer is used to encrypt data in buffer with 256 bit key.
void EncryptBuffer(void* buf, uint size, byte* key, byte* iv);

// DecryptBuffer is used to decrypt data in buffer with 256 bit key.
void DecryptBuffer(void* buf, uint size, byte* key, byte* iv);

// ObfuscateBuffer is used to obfuscate memory data, it is used to
// preserve statistical characteristics as much as possible.
void ObfuscateBuffer(void* buf, uint size, uint64 key);

// IlluminateBuffer is used to recover obfuscated memory data.
void IlluminateBuffer(void* buf, uint size, uint64 key);

// FillInstruction is used to generate instruction to fill the buffer.
void FillInstruction(void* buf, uint size, uint64 seed);

// XORBuffer is used to xor data in buffer with key.
void XORBuffer(void* buf, uint bufSize, void* key, uint keySize);

// SubstituteBuffer is used to replace each byte in the buffer using
// a randomly generated substitution table (S-box).
void SubstituteBuffer(void* buf, uint size);

// ShuffleBuffer is used to randomly permutes the order of bytes in the buffer.
void ShuffleBuffer(void* buf, uint size);

// EraseBuffer is used to erase data in buffer, it will not free memory.
void EraseBuffer(void* buf, uint size);

// EraseInstruction is used to erase instruction, it is used to preserve
// statistical characteristics as much as possible while erasing instructions.
void EraseInstruction(void* buf, uint size);

#endif // CRYPTO_H
