#include "c_types.h"
#include "rel_addr.h"
#include "random.h"

static uint64 generateSeed();
static uint64 getStackAddr();
static uint64 rand(uint64 seed);
static uint64 ror(uint64 value, uint8 bits);

#pragma optimize("t", on)

int RandInt(uint64 seed)
{
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return (int)rand(seed);
}

int8 RandInt8(uint64 seed)
{
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return (int8)rand(seed);
}

int16 RandInt16(uint64 seed)
{
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return (int16)rand(seed);
}

int32 RandInt32(uint64 seed)
{
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return (int32)rand(seed);
}

int64 RandInt64(uint64 seed)
{
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return (int64)rand(seed);
}

uint RandUint(uint64 seed)
{
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return (uint)rand(seed);
}

uint8 RandUint8(uint64 seed)
{
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return (uint8)rand(seed);
}

uint16 RandUint16(uint64 seed)
{
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return (uint16)rand(seed);
}

uint32 RandUint32(uint64 seed)
{
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return (uint32)rand(seed);
}

uint64 RandUint64(uint64 seed)
{
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return rand(seed);
}

int RandIntN(uint64 seed, int n)
{
    if (n <= 0)
    {
        panic(PANIC_INVALID_ARGUMENT);
    }
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return (int)RandUint(seed) % n;
}

int8 RandInt8N(uint64 seed, int8 n)
{
    if (n <= 0)
    {
        panic(PANIC_INVALID_ARGUMENT);
    }
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return (int8)RandUint8(seed) % n;
}

int16 RandInt16N(uint64 seed, int16 n)
{
    if (n <= 0)
    {
        panic(PANIC_INVALID_ARGUMENT);
    }
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return (int16)RandUint16(seed) % n;
}

int32 RandInt32N(uint64 seed, int32 n)
{
    if (n <= 0)
    {
        panic(PANIC_INVALID_ARGUMENT);
    }
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return (int32)RandUint32(seed) % n;
}

int64 RandInt64N(uint64 seed, int64 n)
{
    if (n <= 0)
    {
        panic(PANIC_INVALID_ARGUMENT);
    }
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return (int64)RandUint64(seed) % n;
}

uint RandUintN(uint64 seed, uint n)
{
    if (n <= 0)
    {
        panic(PANIC_INVALID_ARGUMENT);
    }
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return RandUint(seed) % n;
}

uint8 RandUint8N(uint64 seed, uint8 n)
{
    if (n <= 0)
    {
        panic(PANIC_INVALID_ARGUMENT);
    }
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return RandUint8(seed) % n;
}

uint16 RandUint16N(uint64 seed, uint16 n)
{
    if (n <= 0)
    {
        panic(PANIC_INVALID_ARGUMENT);
    }
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return RandUint16(seed) % n;
}

uint32 RandUint32N(uint64 seed, uint32 n)
{
    if (n <= 0)
    {
        panic(PANIC_INVALID_ARGUMENT);
    }
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return RandUint32(seed) % n;
}

uint64 RandUint64N(uint64 seed, uint64 n)
{
    if (n <= 0)
    {
        panic(PANIC_INVALID_ARGUMENT);
    }
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return RandUint64(seed) % n;
}

byte RandByte(uint64 seed)
{
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return (byte)rand(seed);
}

bool RandBool(uint64 seed)
{
    if (seed == 0)
    {
        seed = generateSeed();
    }
    return rand(seed) & 1;
}

BOOL RandBOOL(uint64 seed)
{
    return RandBool(seed);
}

void RandBuffer(void* buf, int64 size)
{
    if (size < 1)
    {
        return;
    }
    byte* buffer = buf;
    // limit the max loop times
    int64 times = size;
    if (times > 16)
    {
        times = 16;
    }
    // generate seed from buffer address
    uint64 seed = generateSeed();
    seed += (uint64)(buffer);
    for (int64 i = 0; i < times; i++)
    {
        byte b = *(buffer + i);
        if (b == 0)
        {
            b = 170;
        }
        seed += ror(seed, b % 4);
        seed *= b;
    }
    for (int64 i = 0; i < size; i++)
    {
        // xor shift
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        // write generate byte
        *(buffer + i) = (byte)seed;
    }
}

void RandSequence(int* array, int n)
{
    // initialize input array
    for (int i = 0; i < n; i++)
    {
        array[i] = i;
    }
    // swap with random index
    uint64 seed = generateSeed();
    for (int i = n - 1; i > 0; i--)
    {
        int j = RandIntN(seed, i + 1);
        int valA = array[i];
        int valB = array[j];
        array[i] = valB;
        array[j] = valA;
        // update seed
        seed = XORShift64(seed);
    }
}

__declspec(noinline)
static uint64 generateSeed()
{
    uint64 seed = GenerateSeed();
    seed *= XORShift64(seed);
    seed += getStackAddr();
    seed ^= XORShift64(seed);
    return seed;
}

#pragma warning(push)
#pragma warning(disable: 4172)
static uint64 getStackAddr()
{
    uint stack = 0;
    return (uint64)(&stack);
}
#pragma warning(pop)

__declspec(noinline)
static uint64 rand(uint64 seed)
{
    uint64 a = (uint64)(GetFuncAddr(&ror));
    uint64 c = (uint64)(GetFuncAddr(&getStackAddr));
    // just play game
    a += ror(a, 3);
    c += ror(c, 32);
    seed += ror(seed + a, 3);
    seed += ror(seed + c, 6);
    seed *= ror(seed, 9) | 1;
    seed ^= ror(seed, 1);
    seed += ror(seed, 17);
    seed = (a * seed + c);
    // xor shift 64
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    return seed;
}

static uint64 ror(uint64 value, uint8 bits)
{
    return value >> bits | value << (64 - bits);
}

__declspec(noinline)
uint XORShift(uint seed)
{
#ifdef _WIN64
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
#elif _WIN32
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
#endif
    return seed;
}

__declspec(noinline)
uint32 XORShift32(uint32 seed)
{
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    return seed;
}

__declspec(noinline)
uint64 XORShift64(uint64 seed)
{
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    return seed;
}

#pragma optimize("t", off)
