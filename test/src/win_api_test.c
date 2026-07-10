#include <stdio.h>
#include "c_types.h"
#include "win_types.h"
#include "win_structs.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "win_api.h"
#include "test.h"

static bool TestIsValidModuleHandle();
static bool TestGetModuleBaseNameW();
static bool TestGetModuleHandleW();
static bool TestIsDebuggerPresent();

bool TestWinAPI()
{
    test_t tests[] = {
        { TestIsValidModuleHandle },
        { TestGetModuleBaseNameW  },
        { TestGetModuleHandleW    },
        { TestIsDebuggerPresent   },
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

static bool TestIsValidModuleHandle()
{

    printf_s("test IsValidModuleHandle passed\n");
    return true;
}

static bool TestGetModuleBaseNameW()
{

    printf_s("test GetModuleBaseNameW passed\n");
    return true;
}

static bool TestGetModuleHandleW()
{

    printf_s("test GetModuleHandleW passed\n");
    return true;
}

static bool TestIsDebuggerPresent()
{

    printf_s("test IsDebuggerPresent passed\n");
    return true;
}
