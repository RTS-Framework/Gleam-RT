#include "c_types.h"
#include "lib_encode.h"

static byte Hex_byte(byte b);
static int  Hex_value(byte s);

uint Hex_Encode(void* src, uint len, byte* dst)
{
    if (dst == NULL)
    {
        return len * 2;
    }
    byte* buf = (byte*)src;
    for (uint i = 0; i < len; i++)
    {
        byte b = buf[i];
        dst[i * 2 + 0] = Hex_byte(b >> 4);
        dst[i * 2 + 1] = Hex_byte(b >> 0);
    }
    return len * 2;
}

static byte Hex_byte(byte v)
{
    v &= 0x0F;
    if (v < 10)
    {
        return '0' + v;
    }
    return 'A' + (v - 10);
}

uint Hex_Decode(byte* src, uint len, void* dst)
{
    if (len & 1)
    {
        return (uint)(-1);
    }
    if (dst == NULL)
    {
        return len / 2;
    }
    byte* buf = (byte*)dst;
    for (uint i = 0; i < len; i += 2)
    {
        int h = Hex_value(src[i + 0]);
        int l = Hex_value(src[i + 1]);
        if (h < 0 || l < 0)
        {
            return (uint)(-1);
        }
        buf[i / 2] = (byte)(h * 16 + l);
    }
    return len / 2;
}

static int Hex_value(byte s)
{
    if (s >= '0' && s <= '9')
    {
        return s - '0';
    }
    if (s >= 'a' && s <= 'f')
    {
        return s - 'a' + 10;
    }
    if (s >= 'A' && s <= 'F')
    {
        return s - 'A' + 10;
    }
    return -1;
}
