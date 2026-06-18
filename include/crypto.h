#ifndef CRYPTO_H
#define CRYPTO_H

#include "c_types.h"

#define CRYPTO_IV_SIZE  16
#define CRYPTO_KEY_SIZE 32

// EncryptBuffer is used to encrypt data in buffer with 256 bit key.
void EncryptBuffer(void* buf, uint size, byte* key, byte* iv);

// DecryptBuffer is used to decrypt data in buffer with 256 bit key.
void DecryptBuffer(void* buf, uint size, byte* key, byte* iv);

// XORBuffer is used to xor data in buffer with key.
void XORBuffer(void* buf, uint bufSize, void* key, uint keySize);

// EraseBuffer is used to erase data in buffer, it not free memory.
void EraseBuffer(void* buf, uint size);

#endif // CRYPTO_H
