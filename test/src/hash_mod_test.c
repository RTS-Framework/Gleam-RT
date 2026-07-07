#include <stdio.h>
#include "c_types.h"
#include "hash_mod.h"
#include "test.h"

static bool TestHashModule();

bool TestHashMod()
{
    test_t tests[] =
    {
        { TestHashModule },
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

static bool TestHashModule()
{
    uint64 hash = HashMod(L"test_main.exe");
    if (hash != 0x423E72AF5A54CD53)
    {
        printf_s("invalid module hash\n");
        return false;
    }
    printf_s("test HashMod passed\n");
    return true;
}
