#include "build.h"
#include "c_types.h"
#include "lib_memory.h"
#include "random.h"
#include "crypto.h"

// !!!!!!!!  It is NOT cryptographically secure  !!!!!!!!!
//
// The main purpose of this symmetric encryption algorithm
// is to encrypt the data in the memory so that it looks
// like there is no obvious pattern.
//
// It's main design goal is to be as small as possible and
// not to use a simple XOR encryption.

#define PARALLEL_LEVEL 8

static void encryptBuffer(byte* buf, uint size, byte* key, byte* iv, byte* sbox);
static void decryptBuffer(byte* buf, uint size, byte* key, byte* iv, byte* sbox);
static void initSBox(byte* sbox, byte* key, byte* iv);
static void reverseSBox(byte* sbox);
static byte ror(byte value, uint8 bits);
static byte rol(byte value, uint8 bits);

#pragma optimize("t", on)
void EncryptBuffer(void* buf, uint size, byte* key, byte* iv)
{
    if (size == 0)
    {
        return;
    }
    byte sbox[256];
    initSBox(sbox, key, iv);
    encryptBuffer(buf, size, key, iv, sbox);
}

static void encryptBuffer(byte* buf, uint size, byte* key, byte* iv, byte* sbox)
{
    // prepare seed from key
    uint32 seeds[8] = {
        *(uint32*)(key+0x00), *(uint32*)(key+0x04),
        *(uint32*)(key+0x08), *(uint32*)(key+0x0C),
        *(uint32*)(key+0x10), *(uint32*)(key+0x14),
        *(uint32*)(key+0x18), *(uint32*)(key+0x1C),
    };
    // initialize random seeds
    for (int i = 0; i < 8; i++)
    {
        uint32 seed = seeds[i];

        seed *= (uint32)(key[i * 4 + 0]) << 0;
        seed *= (uint32)(key[i * 4 + 1]) << 8;
        seed *= (uint32)(key[i * 4 + 2]) << 16;
        seed *= (uint32)(key[i * 4 + 3]) << 24;

        seed ^= (uint32)(key[i * 4 + 0]) << 0;
        seed ^= (uint32)(key[i * 4 + 1]) << 8;
        seed ^= (uint32)(key[i * 4 + 2]) << 16;
        seed ^= (uint32)(key[i * 4 + 3]) << 24;

        seed ^= (uint32)(iv[i * 2 + 0]) << 8;
        seed ^= (uint32)(iv[i * 2 + 1]) << 24;

        seeds[i] = seed;
    }

    // load random seeds
    register uint32 seed0 = seeds[0];
    register uint32 seed1 = seeds[1];
    register uint32 seed2 = seeds[2];
    register uint32 seed3 = seeds[3];
    register uint32 seed4 = seeds[4];
    register uint32 seed5 = seeds[5];
    register uint32 seed6 = seeds[6];
    register uint32 seed7 = seeds[7];

    byte last  = key[0] + iv[0];
    uint limit = size - (size % PARALLEL_LEVEL);
    for (uint i = 0; i < limit; i += PARALLEL_LEVEL)
    {
        // update seeds
        seed0 = XORShift32(seed0);
        seed1 = XORShift32(seed1);
        seed2 = XORShift32(seed2);
        seed3 = XORShift32(seed3);
        seed4 = XORShift32(seed4);
        seed5 = XORShift32(seed5);
        seed6 = XORShift32(seed6);
        seed7 = XORShift32(seed7);

        // load plain data
        uint64 block = *(uint64*)(buf + i);
        register byte b0 = (byte)(block >> 0);
        register byte b1 = (byte)(block >> 8);
        register byte b2 = (byte)(block >> 16);
        register byte b3 = (byte)(block >> 24);
        register byte b4 = (byte)(block >> 32);
        register byte b5 = (byte)(block >> 40);
        register byte b6 = (byte)(block >> 48);
        register byte b7 = (byte)(block >> 56);

        // substitution
        b0 = sbox[b0];
        b1 = sbox[b1];
        b2 = sbox[b2];
        b3 = sbox[b3];
        b4 = sbox[b4];
        b5 = sbox[b5];
        b6 = sbox[b6];
        b7 = sbox[b7];

        b0 ^= seed0;
        b1 ^= seed1;
        b2 ^= seed2;
        b3 ^= seed3;
        b4 ^= seed4;
        b5 ^= seed5;
        b6 ^= seed6;
        b7 ^= seed7;

        b0 = ror(b0, (seed0 >> 8) % 8);
        b1 = ror(b1, (seed1 >> 8) % 8);
        b2 = ror(b2, (seed2 >> 8) % 8);
        b3 = ror(b3, (seed3 >> 8) % 8);
        b4 = ror(b4, (seed4 >> 8) % 8);
        b5 = ror(b5, (seed5 >> 8) % 8);
        b6 = ror(b6, (seed6 >> 8) % 8);
        b7 = ror(b7, (seed7 >> 8) % 8);

        b0 ^= seed0 >> 8;
        b1 ^= seed1 >> 8;
        b2 ^= seed2 >> 8;
        b3 ^= seed3 >> 8;
        b4 ^= seed4 >> 8;
        b5 ^= seed5 >> 8;
        b6 ^= seed6 >> 8;
        b7 ^= seed7 >> 8;

        b0 = ror(b0, (seed0 >> 16) % 8);
        b1 = ror(b1, (seed1 >> 16) % 8);
        b2 = ror(b2, (seed2 >> 16) % 8);
        b3 = ror(b3, (seed3 >> 16) % 8);
        b4 = ror(b4, (seed4 >> 16) % 8);
        b5 = ror(b5, (seed5 >> 16) % 8);
        b6 = ror(b6, (seed6 >> 16) % 8);
        b7 = ror(b7, (seed7 >> 16) % 8);

        b0 ^= (seed0 >> 16);
        b1 ^= (seed1 >> 16);
        b2 ^= (seed2 >> 16);
        b3 ^= (seed3 >> 16);
        b4 ^= (seed4 >> 16);
        b5 ^= (seed5 >> 16);
        b6 ^= (seed6 >> 16);
        b7 ^= (seed7 >> 16);

        b0 = ror(b0, (seed0 >> 24) % 8);
        b1 = ror(b1, (seed1 >> 24) % 8);
        b2 = ror(b2, (seed2 >> 24) % 8);
        b3 = ror(b3, (seed3 >> 24) % 8);
        b4 = ror(b4, (seed4 >> 24) % 8);
        b5 = ror(b5, (seed5 >> 24) % 8);
        b6 = ror(b6, (seed6 >> 24) % 8);
        b7 = ror(b7, (seed7 >> 24) % 8);

        b0 ^= (seed0 >> 24);
        b1 ^= (seed1 >> 24);
        b2 ^= (seed2 >> 24);
        b3 ^= (seed3 >> 24);
        b4 ^= (seed4 >> 24);
        b5 ^= (seed5 >> 24);
        b6 ^= (seed6 >> 24);
        b7 ^= (seed7 >> 24);

        // substitution
        b0 = sbox[b0];
        b1 = sbox[b1];
        b2 = sbox[b2];
        b3 = sbox[b3];
        b4 = sbox[b4];
        b5 = sbox[b5];
        b6 = sbox[b6];
        b7 = sbox[b7];

        // diffuse cipher data
        b0 ^= last;
        b1 ^= b0;
        b2 ^= b1;
        b3 ^= b2;
        b4 ^= b3;
        b5 ^= b4;
        b6 ^= b5;
        b7 ^= b6;

        // update the last
        last = b7;

        // store cipher data
        block = 0;
        block += (uint64)(b0) << 0;
        block += (uint64)(b1) << 8;
        block += (uint64)(b2) << 16;
        block += (uint64)(b3) << 24;
        block += (uint64)(b4) << 32;
        block += (uint64)(b5) << 40;
        block += (uint64)(b6) << 48;
        block += (uint64)(b7) << 56;
        *(uint64*)(buf + i) = block;

        // diffuse seed
        uint32 diff0 = (uint32)(block >> 0);
        uint32 diff1 = (uint32)(block >> 32);
        seed0 ^= diff0;
        seed1 ^= diff0;
        seed2 ^= diff0;
        seed3 ^= diff0;
        seed4 ^= diff1;
        seed5 ^= diff1;
        seed6 ^= diff1;
        seed7 ^= diff1;
    }

    // update random seeds
    seeds[0] = seed0;
    seeds[1] = seed1;
    seeds[2] = seed2;
    seeds[3] = seed3;
    seeds[4] = seed4;
    seeds[5] = seed5;
    seeds[6] = seed6;
    seeds[7] = seed7;

    // process remaining not aligned data
    for (uint i = limit; i < size; i++)
    {
        // get and update seed
        uint32 seed = seeds[i % 8];
        seed = XORShift32(seed);

        // load plain data
        byte b = buf[i];

        // substitution
        b = sbox[b];

        // xor and ror
        b ^= seed;
        b = ror(b, (seed >> 8 ) % 8);
        b ^= seed >> 8;
        b = ror(b, (seed >> 16) % 8);
        b ^= seed >> 16;
        b = ror(b, (seed >> 24) % 8);
        b ^= seed >> 24;

        // substitution
        b = sbox[b];

        // diffuse cipher data
        b ^= last;

        // update the last
        last = b;

        // store cipher data
        buf[i] = b;
    }
}

void DecryptBuffer(void* buf, uint size, byte* key, byte* iv)
{
    if (size == 0)
    {
        return;
    }
    byte sbox[256];
    initSBox(sbox, key, iv);
    reverseSBox(sbox);
    decryptBuffer(buf, size, key, iv, sbox);
}

static void decryptBuffer(byte* buf, uint size, byte* key, byte* iv, byte* sbox)
{
    // prepare seed from key
    uint32 seeds[8] = {
        *(uint32*)(key+0x00), *(uint32*)(key+0x04),
        *(uint32*)(key+0x08), *(uint32*)(key+0x0C),
        *(uint32*)(key+0x10), *(uint32*)(key+0x14),
        *(uint32*)(key+0x18), *(uint32*)(key+0x1C),
    };
    // initialize random seeds
    for (int i = 0; i < 8; i++)
    {
        uint32 seed = seeds[i];

        seed *= (uint32)(key[i * 4 + 0]) << 0;
        seed *= (uint32)(key[i * 4 + 1]) << 8;
        seed *= (uint32)(key[i * 4 + 2]) << 16;
        seed *= (uint32)(key[i * 4 + 3]) << 24;

        seed ^= (uint32)(key[i * 4 + 0]) << 0;
        seed ^= (uint32)(key[i * 4 + 1]) << 8;
        seed ^= (uint32)(key[i * 4 + 2]) << 16;
        seed ^= (uint32)(key[i * 4 + 3]) << 24;

        seed ^= (uint32)(iv[i * 2 + 0]) << 8;
        seed ^= (uint32)(iv[i * 2 + 1]) << 24;

        seeds[i] = seed;
    }

    // load random seeds
    register uint32 seed0 = seeds[0];
    register uint32 seed1 = seeds[1];
    register uint32 seed2 = seeds[2];
    register uint32 seed3 = seeds[3];
    register uint32 seed4 = seeds[4];
    register uint32 seed5 = seeds[5];
    register uint32 seed6 = seeds[6];
    register uint32 seed7 = seeds[7];

    byte last  = key[0] + iv[0];
    uint limit = size - (size % PARALLEL_LEVEL);
    for (uint i = 0; i < limit; i += PARALLEL_LEVEL)
    {
        // update seeds
        seed0 = XORShift32(seed0);
        seed1 = XORShift32(seed1);
        seed2 = XORShift32(seed2);
        seed3 = XORShift32(seed3);
        seed4 = XORShift32(seed4);
        seed5 = XORShift32(seed5);
        seed6 = XORShift32(seed6);
        seed7 = XORShift32(seed7);

        // load cipher data
        uint64 block = *(uint64*)(buf + i);
        register byte b0 = (byte)(block >> 0);
        register byte b1 = (byte)(block >> 8);
        register byte b2 = (byte)(block >> 16);
        register byte b3 = (byte)(block >> 24);
        register byte b4 = (byte)(block >> 32);
        register byte b5 = (byte)(block >> 40);
        register byte b6 = (byte)(block >> 48);
        register byte b7 = (byte)(block >> 56);

        // record cipher data
        byte lastc = b7;

        // diffuse cipher data
        b7 ^= b6;
        b6 ^= b5;
        b5 ^= b4;
        b4 ^= b3;
        b3 ^= b2;
        b2 ^= b1;
        b1 ^= b0;
        b0 ^= last;

        // update the last
        last = lastc;

        // substitution
        b0 = sbox[b0];
        b1 = sbox[b1];
        b2 = sbox[b2];
        b3 = sbox[b3];
        b4 = sbox[b4];
        b5 = sbox[b5];
        b6 = sbox[b6];
        b7 = sbox[b7];

        b0 ^= (seed0 >> 24);
        b1 ^= (seed1 >> 24);
        b2 ^= (seed2 >> 24);
        b3 ^= (seed3 >> 24);
        b4 ^= (seed4 >> 24);
        b5 ^= (seed5 >> 24);
        b6 ^= (seed6 >> 24);
        b7 ^= (seed7 >> 24);

        b0 = rol(b0, (seed0 >> 24) % 8);
        b1 = rol(b1, (seed1 >> 24) % 8);
        b2 = rol(b2, (seed2 >> 24) % 8);
        b3 = rol(b3, (seed3 >> 24) % 8);
        b4 = rol(b4, (seed4 >> 24) % 8);
        b5 = rol(b5, (seed5 >> 24) % 8);
        b6 = rol(b6, (seed6 >> 24) % 8);
        b7 = rol(b7, (seed7 >> 24) % 8);

        b0 ^= (seed0 >> 16);
        b1 ^= (seed1 >> 16);
        b2 ^= (seed2 >> 16);
        b3 ^= (seed3 >> 16);
        b4 ^= (seed4 >> 16);
        b5 ^= (seed5 >> 16);
        b6 ^= (seed6 >> 16);
        b7 ^= (seed7 >> 16);

        b0 = rol(b0, (seed0 >> 16) % 8);
        b1 = rol(b1, (seed1 >> 16) % 8);
        b2 = rol(b2, (seed2 >> 16) % 8);
        b3 = rol(b3, (seed3 >> 16) % 8);
        b4 = rol(b4, (seed4 >> 16) % 8);
        b5 = rol(b5, (seed5 >> 16) % 8);
        b6 = rol(b6, (seed6 >> 16) % 8);
        b7 = rol(b7, (seed7 >> 16) % 8);

        b0 ^= seed0 >> 8;
        b1 ^= seed1 >> 8;
        b2 ^= seed2 >> 8;
        b3 ^= seed3 >> 8;
        b4 ^= seed4 >> 8;
        b5 ^= seed5 >> 8;
        b6 ^= seed6 >> 8;
        b7 ^= seed7 >> 8;

        b0 = rol(b0, (seed0 >> 8) % 8);
        b1 = rol(b1, (seed1 >> 8) % 8);
        b2 = rol(b2, (seed2 >> 8) % 8);
        b3 = rol(b3, (seed3 >> 8) % 8);
        b4 = rol(b4, (seed4 >> 8) % 8);
        b5 = rol(b5, (seed5 >> 8) % 8);
        b6 = rol(b6, (seed6 >> 8) % 8);
        b7 = rol(b7, (seed7 >> 8) % 8);

        b0 ^= seed0;
        b1 ^= seed1;
        b2 ^= seed2;
        b3 ^= seed3;
        b4 ^= seed4;
        b5 ^= seed5;
        b6 ^= seed6;
        b7 ^= seed7;

        // substitution
        b0 = sbox[b0];
        b1 = sbox[b1];
        b2 = sbox[b2];
        b3 = sbox[b3];
        b4 = sbox[b4];
        b5 = sbox[b5];
        b6 = sbox[b6];
        b7 = sbox[b7];

        // diffuse seed
        uint32 diff0 = (uint32)(block >> 0);
        uint32 diff1 = (uint32)(block >> 32);
        seed0 ^= diff0;
        seed1 ^= diff0;
        seed2 ^= diff0;
        seed3 ^= diff0;
        seed4 ^= diff1;
        seed5 ^= diff1;
        seed6 ^= diff1;
        seed7 ^= diff1;

        // store plain data
        block = 0;
        block += (uint64)(b0) << 0;
        block += (uint64)(b1) << 8;
        block += (uint64)(b2) << 16;
        block += (uint64)(b3) << 24;
        block += (uint64)(b4) << 32;
        block += (uint64)(b5) << 40;
        block += (uint64)(b6) << 48;
        block += (uint64)(b7) << 56;
        *(uint64*)(buf + i) = block;
    }

    // update random seeds
    seeds[0] = seed0;
    seeds[1] = seed1;
    seeds[2] = seed2;
    seeds[3] = seed3;
    seeds[4] = seed4;
    seeds[5] = seed5;
    seeds[6] = seed6;
    seeds[7] = seed7;

    // process remaining not aligned data
    for (uint i = limit; i < size; i++)
    {
        // get and update seed
        uint32 seed = seeds[i % 8];
        seed = XORShift32(seed);

        // load cipher data
        byte b = buf[i];

        // record cipher data
        byte lastc = b;

        // diffuse cipher data
        b ^= last;

        // update the last
        last = lastc;

        // substitution
        b = sbox[b];

       // xor and rol
        b ^= seed >> 24;
        b = rol(b, (seed >> 24) % 8);
        b ^= seed >> 16;
        b = rol(b, (seed >> 16) % 8);
        b ^= seed >> 8;
        b = rol(b, (seed >> 8 ) % 8);
        b ^= seed;

        // substitution
        b = sbox[b];

        // store plain data
        buf[i] = b;
    }
}

static void initSBox(byte* sbox, byte* key, byte* iv)
{
    // initialize S-Box byte array
    mem_init(sbox, 256);
    for (uint i = 0; i < 256; i++)
    {
        sbox[i] = (byte)i;
    }
    // initialize seed for XOR Shift;
    uint64 seed = *(uint64*)key;
    for (int i = 0; i < CRYPTO_KEY_SIZE; i++)
    {
        seed += *(key + i);
    }
    for (int i = 0; i < CRYPTO_IV_SIZE; i++)
    {
        seed ^= *(iv + i);
    }
    // generate S-Box from seed
    for (uint i = 255; i > 0; i--)
    {
        uint j = RandUintN(seed, i + 1);
        byte t = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = t;
        // update seed
        seed = XORShift64(seed);
    }
}

static void reverseSBox(byte* sbox)
{
    byte buf[256];
    mem_copy(buf, sbox, sizeof(buf));
    for (int i = 0; i < 256; i++)
    {
        sbox[buf[i]] = (byte)i;
    }
}

static byte ror(byte value, uint8 bits)
{
    if (bits == 0)
    {
        return value;
    }
    return value >> bits | value << (8 - bits);
}

static byte rol(byte value, uint8 bits)
{
    if (bits == 0)
    {
        return value;
    }
    return value << bits | value >> (8 - bits);
}
#pragma optimize("t", off)

#pragma optimize("t", on)
void XORBuffer(void* buf, uint bufSize, void* key, uint keySize)
{
    if (bufSize == 0 || keySize == 0)
    {
        return;
    }
    byte* b = buf;
    byte* k = key;
    for (uint i = 0; i < bufSize; i++)
    {
        b[i] ^= k[i%keySize];
    }
}
#pragma optimize("t", off)

#pragma optimize("t", on)
void SubstituteBuffer(void* buf, uint size)
{
    if (size == 0)
    {
        return;
    }
    byte* buffer = buf;
    // generate a random S-box.
    byte sbox[256];
    mem_init(sbox, sizeof(sbox));
    for (uint i = 0; i < 256; i++)
    {
        sbox[i] = (byte)i;
    }
    ShuffleBuffer(sbox, sizeof(sbox));
    // substitute buffer.
    for (uint i = 0; i < size; i++)
    {
        buffer[i] = sbox[buffer[i]];
    }
}
#pragma optimize("t", off)

#pragma optimize("t", on)
void ShuffleBuffer(void* buf, uint size)
{
    if (size <= 1)
    {
        return;
    }
    byte* buffer = buf;
    uint64  seed = GenerateSeed();
    for (uint i = size - 1; i > 0; i--)
    {
        uint j = RandUintN(seed, i + 1);
        byte t = buffer[i];
        buffer[i] = buffer[j];
        buffer[j] = t;
        // update seed
        seed = XORShift64(seed);
    }
}
#pragma optimize("t", off)

#pragma optimize("", off)
void EraseBuffer(void* buf, uint size)
{
    if (size == 0)
    {
        return;
    }
    RandBuffer(buf, size);
    mem_init(buf, size);
}
#pragma optimize("", on)

#pragma optimize("t", on)
void EraseInstruction(void* buf, uint size)
{
    if (size == 0)
    {
        return;
    }
    byte*  inst = buf;
    uint64 seed = GenerateSeed();
    while (size)
    {   
        // update seed
        seed = XORShift64(seed);
        // select operation
        uint n = RandUintN(seed, 100);
        // 30% random bytes.
        if (n < 30)
        {
            uint len = RandUintN(seed, 8) + 1;
            if (len > size)
            {
                len = size;
            }
            for (uint i = 0; i < len; i++)
            {
                inst[i] = RandByte(seed);
            }

            inst += len;
            size -= len;
            continue;
        }
        // 10% push/pop.
        if (n < 40)
        {
            if (RandBool(seed))
            {
                *inst = 0x50 + RandUint8N(seed, 8);
            } else {
                *inst = 0x58 + RandUint8N(seed, 8);
            }

            inst++;
            size--;
            continue;
        }
        // 10% ret/int3/nop.
        if (n < 50)
        {
            byte op;
            switch (RandUint8N(seed, 3))
            {
            case 0:
                op = 0x90;
                break;
            case 1:
                op = 0xC3;
                break;
            default:
                op = 0xCC;
                break;
            }
            *inst = op;

            inst++;
            size--;
            continue;
        }
        // mov/xor/test/add/sub/cmp
        if (size >= 2)
        {
            byte ops[] = {
                0x89, 0x8B, 0x31, 0x33,
                0x85, 0x39, 0x3B, 0x01,
                0x03, 0x29,
            };
            // ModRM = register-direct.
            inst[0] = ops[RandUint8N(seed, arrlen(ops))];
            inst[1] = 0xC0 | (RandUint8N(seed, 8) << 3) | RandUint8N(seed, 8);

            inst += 2;
            size -= 2;
            continue;
        }
        // padding remaining area
        *inst = RandByte(seed);

        inst++;
        size--;
    }
}
#pragma optimize("t", off)
