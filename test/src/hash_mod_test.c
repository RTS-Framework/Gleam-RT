#include <stdio.h>
#include "c_types.h"
#include "lib_string.h"
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
    uint16* module = L"test_main.exe";

    uint64 hash = HashMod(module, strlen_w(module));
    if (hash != 0x4E8B01B5BB7B24DB)
    {
        printf_s("invalid module hash\n");
        return false;
    }
    printf_s("test HashMod passed\n");
    return true;
}
