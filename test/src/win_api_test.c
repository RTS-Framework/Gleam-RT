#include <stdio.h>
#include "c_types.h"
#include "win_types.h"
#include "win_structs.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "hash_api.h"
#include "win_api.h"
#include "test.h"

static bool TestIsValidModuleHandle();
static bool TestGetModuleBaseName();
static bool TestGetModuleHandle();
static bool TestGetProcedureName();

bool TestWinAPI()
{
    test_t tests[] = {
        { TestIsValidModuleHandle },
        { TestGetModuleBaseName   },
        { TestGetModuleHandle     },
        { TestGetProcedureName    },
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
    HMODULE hKernel32 = FindMod_A("kernel32.dll");
    if (hKernel32 == NULL)
    {
        printf_s("failed to get handle of kernel32.dll\n");
        return false;
    }

    PML* pml = GetDefaultPML();
    if (!IsValidModuleHandle(pml, hKernel32))
    {
        printf_s("kernel32.dll handle is invalid\n");
        return false;
    }

    printf_s("test IsValidModuleHandle passed\n");
    return true;
}

static bool TestGetModuleBaseName()
{
    HMODULE hKernel32 = FindMod_A("kernel32.dll");
    if (hKernel32 == NULL)
    {
        printf_s("failed to get handle of kernel32.dll\n");
        return false;
    }
    PML* pml = GetDefaultPML();
    
    // common usage
    WCHAR nameBuf[MAX_PATH];
    mem_init(nameBuf, sizeof(nameBuf));
    DWORD nameLen = GetModuleBaseName(pml, hKernel32, nameBuf, MAX_PATH);
    if (nameLen == 0)
    {
        printf_s("failed to get module base name\n");
        return false;
    }
    if (stricmp_w(nameBuf, L"kernel32.dll") != 0)
    {
        printf_s("unexpected module name\n");
        return false;
    }

    // small buffer
    WCHAR smallBuf[5];
    mem_init(smallBuf, sizeof(smallBuf));
    DWORD smallLen = GetModuleBaseName(pml, hKernel32, smallBuf, arrlen(smallBuf));
    if (smallLen == 0)
    {
        printf_s("failed to get module base name with small buffer\n");
        return false;
    }
    if (smallLen > 4)
    {
        printf_s("buffer truncation not handled correctly\n");
        return false;
    }

    printf_s("test GetModuleBaseName passed\n");
    return true;
}

static bool TestGetModuleHandle()
{
    HMODULE hKernel32 = FindMod_A("kernel32.dll");
    if (hKernel32 == NULL)
    {
        printf_s("failed to get handle of kernel32.dll\n");
        return false;
    }
    PML* pml = GetDefaultPML();

    // common usage
    HMODULE handle = GetModuleHandle(pml, L"kernel32.dll");
    if (handle == NULL)
    {
        printf_s("failed to get handle of kernel32.dll by name\n");
        return false;
    }
    if (handle != hKernel32)
    {
        printf_s("unexpected kernel32 handle\n");
        return false;
    }

    // test case-insensitive matching
    HMODULE hKernel32Upper = GetModuleHandle(pml, L"KERNEL32.DLL");
    if (hKernel32Upper == NULL)
    {
        printf_s("failed case-insensitive matching\n");
        return false;
    }
    if (hKernel32Upper != hKernel32)
    {
        printf_s("case-insensitive matching returned different handle\n");
        return false;
    }

    // test with non-existent module
    HMODULE hNotExist = GetModuleHandle(pml, L"invalid.dll");
    if (hNotExist != NULL)
    {
        printf_s("should return NULL for non-existent module\n");
        return false;
    }

    // test with empty string
    HMODULE hEmpty = GetModuleHandle(pml, L"");
    if (hEmpty != NULL)
    {
        printf_s("should return NULL for empty string\n");
        return false;
    }

    printf_s("test GetModuleHandle passed\n");
    return true;
}

static bool TestGetProcedureName()
{
    PML* pml = GetDefaultPML();

    HMODULE hKernel32 = FindMod_A("kernel32.dll");
    if (hKernel32 == NULL)
    {
        printf_s("failed to get handle of kernel32.dll\n");
        return false;
    }

    Sleep_t Sleep = FindAPI_A("kernel32.dll", "Sleep");
    if (Sleep == NULL)
    {
        printf_s("kernel32.Sleep is not found\n");
        return false;
    }

    LPSTR procName = GetProcedureName(pml, hKernel32, Sleep);
    if (procName == NULL)
    {
        printf_s("failed to get procedure name\n");
        return false;
    }
    if (!strequ_a(procName, "Sleep"))
    {
        printf_s("invalid procedure name\n");
        return false;
    }

    printf_s("test GetProcedureName passed\n");
    return true;
}
