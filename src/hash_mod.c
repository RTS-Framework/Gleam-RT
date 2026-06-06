#include "c_types.h"

static uint64 ror64(uint64 value, uint64 bits);

uint64 HashMod(uint16* module)
{
    uint64 hash = 0xE3C817DEA9BFE921;
    for (;;)
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
        hash = ror64(hash, 7);
        hash += uint64(c);
        hash = ror64(hash, 3);
        module++;
    }
    return hash;
}

static uint64 ror64(uint64 value, uint64 bits)
{
    return value >> bits | value << (64 - bits);
}
