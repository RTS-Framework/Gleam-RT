#include "c_types.h"
#include "hash_mod.h"

static uint64 ror64(uint64 value, uint64 bits);

uint64 HashMod(uint16* module, uint size)
{
    uint64 hash = 0xFFFFFFFF;
    for (uint i = 0; i < size; i++)
    {
        uint16 c = *module;
        if (c == 0x0000)
        {
            break;
        }
        if (c >= 'a' && c <= 'z')
        {
            c -= 0x20;
        }
        hash *= ror64(hash|1, 11);
        hash += c;
        hash ^= ror64(hash|1, 17);
        module++;
    }
    return hash;
}

static uint64 ror64(uint64 value, uint64 bits)
{
    return value >> bits | value << (64 - bits);
}
