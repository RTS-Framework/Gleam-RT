#include "c_types.h"
#include "lib_memory.h"
#include "lib_algo.h"

// ================================SHA256================================

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

void SHA256_transform(SHA256_Ctx* ctx, byte* data);

__declspec(noinline)
void SHA256_Init(SHA256_Ctx *ctx)
{
    ctx->bitlen  = 0;
    ctx->datalen = 0;

    ctx->state[0] = 0x6A09E667;
    ctx->state[1] = 0xBB67AE85;
    ctx->state[2] = 0x3C6EF372;
    ctx->state[3] = 0xA54FF53A;
    ctx->state[4] = 0x510E527F;
    ctx->state[5] = 0x9B05688C;
    ctx->state[6] = 0x1F83D9AB;
    ctx->state[7] = 0x5BE0CD19;
}

__declspec(noinline)
void SHA256_Write(SHA256_Ctx *ctx, void* data, uint len)
{
    byte* array = (byte*)data;
    for (uint i = 0; i < len; i++)
    {
        ctx->data[ctx->datalen] = array[i];
        ctx->datalen++;

        if (ctx->datalen == 64) {
            SHA256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

__declspec(noinline)
void SHA256_Sum(SHA256_Ctx* ctx, byte (*hash)[32])
{
    uint8 i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        mem_init(ctx->data + i, (uint)56 - i);
    } else {
        ctx->data[i++] = 0x80;
        mem_init(ctx->data + i, (uint)64 - i);

        SHA256_transform(ctx, ctx->data);
        mem_init(ctx->data, 56);
    }

    ctx->bitlen += (uint64)(ctx->datalen) * 8;

    ctx->data[63] = (byte)(ctx->bitlen >> 0);
    ctx->data[62] = (byte)(ctx->bitlen >> 8);
    ctx->data[61] = (byte)(ctx->bitlen >> 16);
    ctx->data[60] = (byte)(ctx->bitlen >> 24);
    ctx->data[59] = (byte)(ctx->bitlen >> 32);
    ctx->data[58] = (byte)(ctx->bitlen >> 40);
    ctx->data[57] = (byte)(ctx->bitlen >> 48);
    ctx->data[56] = (byte)(ctx->bitlen >> 56);

    SHA256_transform(ctx, ctx->data);

    for (i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            (*hash)[i + (j << 2)] = (ctx->state[j] >> (24 - i * 8)) & 0xFF;
        }
    }
}

__declspec(noinline)
void SHA256_transform(SHA256_Ctx* ctx, byte* data)
{
    uint32 k[64] = {
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    };

    uint32 m[64];
    uint32 a, b, c, d, e, f, g, h;

    mem_init(m, sizeof(m));

    for (int i = 0; i < 16; i++) {
        m[i] = (data[i*4]<<24)|(data[i*4+1]<<16)|(data[i*4+2]<<8)|(data[i*4+3]);
    }

    for (int i = 16; i < 64; i++) {
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        uint32 t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        uint32 t2 = EP0(a) + MAJ(a,b,c);

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}


// =================================HEX==================================

static byte Hex_byte(byte b);
static int  Hex_value(byte s);

uint Hex_Encode(void* src, uint len, byte* dst)
{
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
        return 0;
    }
    byte* buf = (byte*)dst;
    for (uint i = 0; i < len; i += 2)
    {
        int h = Hex_value(src[i + 0]);
        int l = Hex_value(src[i + 1]);
        if (h < 0 || l < 0)
        {
            return 0;
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
