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
    byte s[] = { 1, 2, 3, 4 };

    // small

    // large


    printf_s("test SHA256 passed\n");
    return true;
}
