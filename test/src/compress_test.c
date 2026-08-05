#include <stdio.h>
#include "c_types.h"
#include "lib_memory.h"
#include "random.h"
#include "compress.h"
#include "test.h"

static bool TestCompressor_SHashCandidate();
static bool TestCompressor_NHashCandidate();
static bool TestCompressor_BruteForce();
static bool TestCompressor_DefaultArgument();
static bool TestCompressor_Fuzz();

bool TestCompress()
{
    test_t tests[] = 
    {
        { TestCompressor_SHashCandidate  },
        { TestCompressor_NHashCandidate  },
        { TestCompressor_BruteForce      },
        { TestCompressor_DefaultArgument },
        { TestCompressor_Fuzz            },
    };
    for (int i = 0; i < arrlen(tests); i++)
    {
        printf_s("--------------------------------\n");
        if (!tests[i]())
        {
            return false;
        }
        printf_s("--------------------------------\n\n");
    }
    return true;
}

static bool TestCompressor_SHashCandidate()
{
    LPSTR path = "..\\src\\runtime.c";
    databuf data;
    errno errno = runtime->WinFile.ReadFileA(path, &data);
    if (errno != NO_ERROR)
    {
        printf_s("failed to read test file: 0x%X\n", errno);
        return false;
    }

    uint windows[] = {
        32, 64, 128, 256, 512, 1024, 1536, 2048, 4096,
    };
    for (int i = 0; i < arrlen(windows); i++)
    {
        uint cl = MINIMUM_CHAIN_LEN;

        uint cLen = runtime->Compressor.Compress(NULL, data.buf, data.len, windows[i], cl);
        printf_s("compressed: %zu/%zu, window: %zu\n", cLen, data.len, windows[i]);
        void* dst = runtime->Memory.Alloc(cLen);
        cLen = runtime->Compressor.Compress(dst, data.buf, data.len, windows[i], cl);
        
        uint dLen = runtime->Compressor.Decompress(NULL, dst, cLen);
        void* raw = runtime->Memory.Alloc(dLen);
        dLen = runtime->Compressor.Decompress(raw, dst, cLen);
        printf_s("decompressed: %zu\n", dLen);
        
        if (dLen != data.len)
        {
            printf_s("incorrect decompressed data size: %zu\n", dLen);
            return false;
        }
        if (mem_cmp(data.buf, raw, data.len) != 0)
        {
            printf_s("incorrect decompressed data\n");
            return false;
        }

        runtime->Memory.Free(dst);
        runtime->Memory.Free(raw);
    }

    runtime->Memory.Free(data.buf);
    printf_s("test compress single hash candidate passed\n");
    return true;
}

static bool TestCompressor_NHashCandidate()
{
    LPSTR path = "..\\src\\runtime.c";
    databuf data;
    errno errno = runtime->WinFile.ReadFileA(path, &data);
    if (errno != NO_ERROR)
    {
        printf_s("failed to read test file: 0x%X\n", errno);
        return false;
    }

    uint windows[] = {
        32, 64, 128, 256, 512, 1024, 1536, 2048, 4096,
    };
    for (int i = 0; i < arrlen(windows); i++)
    {
        uint cl = DEFAULT_CHAIN_LEN;

        uint cLen = runtime->Compressor.Compress(NULL, data.buf, data.len, windows[i], cl);
        printf_s("compressed: %zu/%zu, window: %zu\n", cLen, data.len, windows[i]);
        void* dst = runtime->Memory.Alloc(cLen);
        cLen = runtime->Compressor.Compress(dst, data.buf, data.len, windows[i], cl);
        
        uint dLen = runtime->Compressor.Decompress(NULL, dst, cLen);
        void* raw = runtime->Memory.Alloc(dLen);
        dLen = runtime->Compressor.Decompress(raw, dst, cLen);
        printf_s("decompressed: %zu\n", dLen);
        
        if (dLen != data.len)
        {
            printf_s("incorrect decompressed data size: %zu\n", dLen);
            return false;
        }
        if (mem_cmp(data.buf, raw, data.len) != 0)
        {
            printf_s("incorrect decompressed data\n");
            return false;
        }

        runtime->Memory.Free(dst);
        runtime->Memory.Free(raw);
    }

    runtime->Memory.Free(data.buf);
    printf_s("test compress n hash candidate passed\n");
    return true;
}

static bool TestCompressor_BruteForce()
{
    LPSTR path = "..\\src\\runtime.c";
    databuf data;
    errno errno = runtime->WinFile.ReadFileA(path, &data);
    if (errno != NO_ERROR)
    {
        printf_s("failed to read test file: 0x%X\n", errno);
        return false;
    }

    uint windows[] = {
        32, 64, 128, 256, 512, 1024, 1536, 2048, 4096,
    };
    for (int i = 0; i < arrlen(windows); i++)
    {
        uint cl = MAXIMUM_CHAIN_LEN;

        uint cLen = runtime->Compressor.Compress(NULL, data.buf, data.len, windows[i], cl);
        printf_s("compressed: %zu/%zu, window: %zu\n", cLen, data.len, windows[i]);
        void* dst = runtime->Memory.Alloc(cLen);
        cLen = runtime->Compressor.Compress(dst, data.buf, data.len, windows[i], cl);
        
        uint dLen = runtime->Compressor.Decompress(NULL, dst, cLen);
        void* raw = runtime->Memory.Alloc(dLen);
        dLen = runtime->Compressor.Decompress(raw, dst, cLen);
        printf_s("decompressed: %zu\n", dLen);
        
        if (dLen != data.len)
        {
            printf_s("incorrect decompressed data size: %zu\n", dLen);
            return false;
        }
        if (mem_cmp(data.buf, raw, data.len) != 0)
        {
            printf_s("incorrect decompressed data\n");
            return false;
        }

        runtime->Memory.Free(dst);
        runtime->Memory.Free(raw);
    }

    runtime->Memory.Free(data.buf);
    printf_s("test compress brute force passed\n");
    return true;
}

static bool TestCompressor_DefaultArgument()
{
    LPSTR path = "..\\src\\runtime.c";
    databuf data;
    errno errno = runtime->WinFile.ReadFileA(path, &data);
    if (errno != NO_ERROR)
    {
        printf_s("failed to read test file: 0x%X\n", errno);
        return false;
    }

    uint cLen = runtime->Compressor.Compress(NULL, data.buf, data.len, 0, 0);
    printf_s("compressed: %zu/%zu\n", cLen, data.len);
    void* dst = runtime->Memory.Alloc(cLen);
    cLen = runtime->Compressor.Compress(dst, data.buf, data.len, 0, 0);
    
    uint dLen = runtime->Compressor.Decompress(NULL, dst, cLen);
    void* raw = runtime->Memory.Alloc(dLen);
    dLen = runtime->Compressor.Decompress(raw, dst, cLen);
    printf_s("decompressed: %zu\n", dLen);
    
    if (dLen != data.len)
    {
        printf_s("incorrect decompressed data size: %zu\n", dLen);
        return false;
    }
    if (mem_cmp(data.buf, raw, data.len) != 0)
    {
        printf_s("incorrect decompressed data\n");
        return false;
    }

    runtime->Memory.Free(dst);
    runtime->Memory.Free(raw);
    runtime->Memory.Free(data.buf);
    printf_s("test compress default argument passed\n");
    return true;
}

static bool TestCompressor_Fuzz()
{
    uint  size = (uint)(32 * 1024);
    byte* data = runtime->Memory.Alloc(size);

    for (int i = 0; i < 100; i++ )
    {
        // padding random data
        uint64 seed = (uint64)(data);
        uint   idx  = 0;
        for (int j = 0; j < 1000; j++)
        {
            switch (RandBool(seed))
            {
            case true:
                for (int k = 0; k < 32; k++)
                {
                    data[idx] = (byte)RandIntN(seed, 4);
                    seed = RandUint64(seed);
                    idx++;
                }
                break;
            case false:
                for (int k = 0; k < 16; k++)
                {
                    data[idx] = (byte)RandIntN(seed, 6);
                    seed = RandUint64(seed);
                    idx++;
                }
                break;
            }
        }

        // single hash candidate
        void* dst = runtime->Memory.Alloc(size + size / 8 + 2);
        uint  len = runtime->Compressor.Compress(dst, data, size, 512, MINIMUM_CHAIN_LEN);
        void* raw = runtime->Memory.Alloc(size);
        len = runtime->Compressor.Decompress(raw, dst, len);
        if (len != size)
        {
            printf_s("incorrect fuzz decompressed(sh) data size: %zu\n", len);
            return false;
        }
        if (mem_cmp(data, raw, size) != 0)
        {
            printf_s("incorrect fuzz decompressed(sh) data\n");
            return false;
        }
        runtime->Memory.Free(dst);
        runtime->Memory.Free(raw);

        // N hash candidate
        dst = runtime->Memory.Alloc(size + size / 8 + 2);
        len = runtime->Compressor.Compress(dst, data, size, 512, DEFAULT_CHAIN_LEN);
        raw = runtime->Memory.Alloc(size);
        len = runtime->Compressor.Decompress(raw, dst, len);
        if (len != size)
        {
            printf_s("incorrect fuzz decompressed(nh) data size: %zu\n", len);
            return false;
        }
        if (mem_cmp(data, raw, size) != 0)
        {
            printf_s("incorrect fuzz decompressed(nh) data\n");
            return false;
        }
        runtime->Memory.Free(dst);
        runtime->Memory.Free(raw);

        // brute force
        dst = runtime->Memory.Alloc(size + size / 8 + 2);
        len = runtime->Compressor.Compress(dst, data, size, 512, MAXIMUM_CHAIN_LEN);
        raw = runtime->Memory.Alloc(size);
        len = runtime->Compressor.Decompress(raw, dst, len);
        if (len != size)
        {
            printf_s("incorrect fuzz decompressed(bf) data size: %zu\n", len);
            return false;
        }
        if (mem_cmp(data, raw, size) != 0)
        {
            printf_s("incorrect fuzz decompressed(bf) data\n");
            return false;
        }
        runtime->Memory.Free(dst);
        runtime->Memory.Free(raw);
    }

    runtime->Memory.Free(data);
    printf_s("test compress fuzz passed\n");
    return true;
}
