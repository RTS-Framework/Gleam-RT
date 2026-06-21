#include <stdio.h>
#include "c_types.h"
#include "lib_memory.h"
#include "lib_algo.h"
#include "test.h"

static bool TestLibAlgo_SHA256();

bool TestLibAlgo()
{
    test_t tests[] = 
    {
        { TestLibAlgo_SHA256 },
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


static bool TestLibAlgo_SHA256()
{
    byte data[] = { 1, 2, 3, 4 };

    SHA256_Ctx ctx;
    byte  hash[32];
    SHA256_Init(&ctx);
    for (int i = 0; i < 1000; i++)
    {
        SHA256_Write(&ctx, data, sizeof(data));
    }
    SHA256_Sum(&ctx, &hash);

    byte expected[] = {
        0xCA, 0x01, 0xCB, 0x69, 0x1B, 0xF1, 0xD6, 0xB4, 
        0xB1, 0x87, 0x2A, 0x7F, 0xF2, 0xFE, 0xFF, 0xA5, 
        0xD3, 0xC9, 0x53, 0xA2, 0xFA, 0x7E, 0x6E, 0x37, 
        0x4C, 0xCB, 0x28, 0xEF, 0x7E, 0x07, 0x57, 0xF0,
    };
    if (!mem_equal(expected, hash, sizeof(hash)))
    {
        printf_s("invalid SHA256 digest\n");
        return false;
    }

    printf_s("test SHA256 passed\n");
    return true;
}
