#include "c_types.h"
#include "lib_encode.h"

static byte Hex_byte(byte b);
static int  Hex_value(byte s);
static void Base64_generateTable(byte enc[64], byte dec[256]);

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
        buf[i / 2] = (byte)((h << 4) | l);
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

uint Base64_Encode(void* src, uint len, byte* dst)
{
    uint outLen = ((len + 2) / 3) * 4;
    if (dst == NULL)
    {
        return outLen;
    }

    byte enc[64];
    byte dec[256];
    Base64_generateTable(enc, dec);

    byte* in = (byte*)src;
    uint i = 0;
    uint j = 0;
    while (i + 2 < len)
    {
        uint v = ((uint)in[i] << 16) | ((uint)in[i + 1] << 8) | in[i + 2];
        dst[j++] = enc[(v >> 18) & 63];
        dst[j++] = enc[(v >> 12) & 63];
        dst[j++] = enc[(v >> 6)  & 63];
        dst[j++] = enc[(v >> 0)  & 63];
        i += 3;
    }

    switch (len - i)
    {
    case 1:
      {
        uint v = ((uint)in[i]) << 16;
        dst[j++] = enc[(v >> 18) & 63];
        dst[j++] = enc[(v >> 12) & 63];
        dst[j++] = '=';
        dst[j++] = '=';
        break;
      }
    case 2:
      {
        uint v = ((uint)in[i] << 16) | ((uint)in[i + 1] << 8);
        dst[j++] = enc[(v >> 18) & 63];
        dst[j++] = enc[(v >> 12) & 63];
        dst[j++] = enc[(v >> 6)  & 63];
        dst[j++] = '=';
        break;
      }
    }
    return outLen;
}

uint Base64_Decode(byte* src, uint len, void* dst)
{
    if ((len & 3) != 0)
    {
        return (uint)(-1);
    }

    uint outLen = (len / 4) * 3;
    if (len != 0)
    {
        if (src[len - 1] == '=')
        {
            outLen--;
        }
        if (src[len - 2] == '=')
        {
            outLen--;
        }
    }
    if (dst == NULL)
    {
        return outLen;
    }

    byte enc[64];
    byte dec[256];
    Base64_generateTable(enc, dec);

    byte* out = (byte*)dst;
    uint i = 0;
    uint j = 0;
    while (i < len)
    {
        if (src[i + 0] == '=' || src[i + 1] == '=')
        {
            return (uint)(-1);
        }
        if (src[i + 2] == '=' && src[i + 3] != '=')
        {
            return (uint)(-1);
        }
        if ((src[i + 2] == '=' || src[i + 3] == '=') && (i + 4 != len))
        {
            return (uint)(-1);
        }

        byte a = dec[src[i + 0]];
        byte b = dec[src[i + 1]];
        byte c = dec[src[i + 2]];
        byte d = dec[src[i + 3]];
        if (src[i + 2] == '=')
        {
            c = 0;
        }
        if (src[i + 3] == '=')
        {
            d = 0;
        }

        if (a == 0xFF || b == 0xFF)
        {
            return (uint)(-1);
        }
        if (src[i + 2] != '=' && c == 0xFF)
        {
            return (uint)(-1);
        }
        if (src[i + 3] != '=' && d == 0xFF)
        {
            return (uint)(-1);
        }

        uint v = ((uint)a << 18) | ((uint)b << 12) | ((uint)c << 6) | d;
        if (j < outLen)
        {
            out[j++] = (byte)(v >> 16);
        }
        if (j < outLen)
        {
            out[j++] = (byte)(v >> 8);
        }
        if (j < outLen)
        {
            out[j++] = (byte)(v >> 0);
        }
        i += 4;
    }
    return outLen;
}

// merge two tables to one function for reduce code size.
static void Base64_generateTable(byte enc[64], byte dec[256])
{
    for (uint i = 0; i < 256; i++)
    {
        dec[i] = 0xFF;
    }
    for (uint i = 0; i < 64; i++)
    {
        byte c;
        if (i < 26)
        {
            c = (byte)('A' + i);
        } else if (i < 52) {
            c = (byte)('a' + (i - 26));
        } else if (i < 62) {
            c = (byte)('0' + (i - 52));
        } else if (i == 62) {
            c = '+';
        } else {
            c = '/';
        }
        enc[i] = c;
        dec[c] = (byte)i;
    }
}
