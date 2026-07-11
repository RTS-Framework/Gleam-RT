#include <stdio.h>
#include "c_types.h"
#include "hash_api.h"
#include "test.h"

// define the procedure about IAT.
typedef void* HMODULE;

__declspec(dllimport)
UINT __stdcall WinExec(LPCSTR lpCmdLine, UINT uCmdShow);

__declspec(dllimport)
HMODULE __stdcall LoadLibraryA(LPSTR module);

__declspec(dllimport)
void* __stdcall GetProcAddress(HMODULE module, LPSTR procedure);

static bool TestFindMod_MH();
static bool TestFindAPI_MA();
static bool TestFindAPI_MH();
static bool TestFindMod_MHL();
static bool TestFindAPI_MAL();
static bool TestFindAPI_MHL();
static bool TestFindMod_A();
static bool TestFindMod_W();
static bool TestFindAPI_A();
static bool TestFindAPI_W();
static bool TestForwarded();
static bool TestNotFound();
static bool TestNULLArgument();
static bool TestCalcModHash32();
static bool TestCalcModHash64();
static bool TestCalcProcHash32();
static bool TestCalcProcHash64();

bool TestHashAPI()
{
    test_t tests[] = 
    {
        { TestFindMod_MH     },
        { TestFindAPI_MA     },
        { TestFindAPI_MH     },
        { TestFindMod_MHL    },
        { TestFindAPI_MAL    },
        { TestFindAPI_MHL    },
        { TestFindMod_A      },
        { TestFindMod_W      },
        { TestFindAPI_A      },
        { TestFindAPI_W      },
        { TestForwarded      },
        { TestNotFound       },
        { TestNULLArgument   },
        { TestCalcModHash32  },
        { TestCalcModHash64  },
        { TestCalcProcHash32 },
        { TestCalcProcHash64 },
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

static bool TestFindMod_MH()
{
    HMODULE expected = LoadLibraryA("kernel32.dll");
    if (expected == NULL)
    {
        printf_s("failed to load kernel32.dll\n");
        return false;
    }

#ifdef _WIN64
    uint key = 0x6A6867C72D518853;
#elif _WIN32
    uint key = 0xCADE960B;
#endif
    byte* module  = "kernel32.dll";
    uint  modHash = CalcModHash_A(module, key);

    void* result = FindMod_MH(modHash, key);
    if (result != expected)
    {
        printf_s("Result:   %llX\n", (uint64)result);
        printf_s("Expected: %llX\n", (uint64)expected);
        printf_s("kernel32.dll address is incorrect\n");
        return false;
    }
    printf_s("kernel32.dll: 0x%llX\n", (uint64)result);
    return true;
}

static bool TestFindAPI_MA()
{
    HMODULE hModule = LoadLibraryA("kernel32.dll");
    if (hModule == NULL)
    {
        printf_s("failed to load kernel32.dll\n");
        return false;
    }

#ifdef _WIN64
    uint key = 0x6A6867C72D518853;
#elif _WIN32
    uint key = 0xCADE960B;
#endif
    byte* procedure = "WinExec";
    uint  procHash  = CalcProcHash(procedure, key);

    void* proc = FindAPI_MA(hModule, procHash, key);
    if (proc != &WinExec)
    {
        printf_s("Result:   %llX\n", (uint64)proc);
        printf_s("Expected: %llX\n", (uint64)(&WinExec));
        printf_s("WinExec address is incorrect\n");
        return false;
    }
    printf_s("WinExec: 0x%llX\n", (uint64)proc);
    return true;
}

static bool TestFindAPI_MH()
{
#ifdef _WIN64
    uint key = 0x6A6867C72D518853;
#elif _WIN32
    uint key = 0xCADE960B;
#endif
    byte* module    = "kernel32.dll";
    byte* procedure = "WinExec";
    uint  modHash   = CalcModHash_A(module, key);
    uint  procHash  = CalcProcHash(procedure, key);

    void* proc = FindAPI_MH(modHash, procHash, key);
    if (proc != &WinExec)
    {
        printf_s("Result:   %llX\n", (uint64)proc);
        printf_s("Expected: %llX\n", (uint64)(&WinExec));
        printf_s("WinExec address is incorrect\n");
        return false;
    }
    printf_s("WinExec: 0x%llX\n", (uint64)proc);
    return true;
}

static bool TestFindMod_MHL()
{
    HMODULE expected = LoadLibraryA("kernel32.dll");
    if (expected == NULL)
    {
        printf_s("failed to load kernel32.dll\n");
        return false;
    }

#ifdef _WIN64
    uint key = 0x6A6867C72D518853;
#elif _WIN32
    uint key = 0xCADE960B;
#endif
    byte* module  = "kernel32.dll";
    uint  modHash = CalcModHash_A(module, key);

    PML*  pml    = GetDefaultPML();
    void* result = FindMod_MHL(pml, modHash, key);
    if (result != expected)
    {
        printf_s("Result:   %llX\n", (uint64)result);
        printf_s("Expected: %llX\n", (uint64)expected);
        printf_s("kernel32.dll address is incorrect\n");
        return false;
    }
    printf_s("kernel32.dll: 0x%llX\n", (uint64)result);
    return true;
}

static bool TestFindAPI_MAL()
{
    HMODULE hModule = LoadLibraryA("kernel32.dll");
    if (hModule == NULL)
    {
        printf_s("failed to load kernel32.dll\n");
        return false;
    }

#ifdef _WIN64
    uint key = 0x6A6867C72D518853;
#elif _WIN32
    uint key = 0xCADE960B;
#endif
    byte* procedure = "WinExec";
    uint  procHash  = CalcProcHash(procedure, key);

    PML*  pml  = GetDefaultPML();
    void* proc = FindAPI_MAL(pml, hModule, procHash, key);
    if (proc != &WinExec)
    {
        printf_s("Result:   %llX\n", (uint64)proc);
        printf_s("Expected: %llX\n", (uint64)(&WinExec));
        printf_s("WinExec address is incorrect\n");
        return false;
    }
    printf_s("WinExec: 0x%llX\n", (uint64)proc);
    return true;
}

static bool TestFindAPI_MHL()
{
#ifdef _WIN64
    uint key = 0x6A6867C72D518853;
#elif _WIN32
    uint key = 0xCADE960B;
#endif
    byte* module    = "kernel32.dll";
    byte* procedure = "WinExec";
    uint  modHash   = CalcModHash_A(module, key);
    uint  procHash  = CalcProcHash(procedure, key);

    PML*  pml  = GetDefaultPML();
    void* proc = FindAPI_MHL(pml, modHash, procHash, key);
    if (proc != &WinExec)
    {
        printf_s("Result:   %llX\n", (uint64)proc);
        printf_s("Expected: %llX\n", (uint64)(&WinExec));
        printf_s("WinExec address is incorrect\n");
        return false;
    }
    printf_s("WinExec: 0x%llX\n", (uint64)proc);
    return true;
}

static bool TestFindMod_A()
{
    HMODULE expected = LoadLibraryA("kernel32.dll");
    if (expected == NULL)
    {
        printf_s("failed to load kernel32.dll\n");
        return false;
    }

    byte* module = "kernel32.dll";
    void* result = FindMod_A(module);
    if (result != expected)
    {
        printf_s("Result:   %llX\n", (uint64)result);
        printf_s("Expected: %llX\n", (uint64)expected);
        printf_s("kernel32.dll address is incorrect\n");
        return false;
    }
    printf_s("kernel32.dll: 0x%llX\n", (uint64)result);
    return true;
}

static bool TestFindMod_W()
{
    HMODULE expected = LoadLibraryA("kernel32.dll");
    if (expected == NULL)
    {
        printf_s("failed to load kernel32.dll\n");
        return false;
    }

    uint16* module = L"kernel32.dll";
    void*   result = FindMod_W(module);
    if (result != expected)
    {
        printf_s("Result:   %llX\n", (uint64)result);
        printf_s("Expected: %llX\n", (uint64)expected);
        printf_s("kernel32.dll address is incorrect\n");
        return false;
    }
    printf_s("kernel32.dll: 0x%llX\n", (uint64)result);
    return true;
}

static bool TestFindAPI_A()
{
    byte* module    = "kernel32.dll";
    byte* procedure = "WinExec";

    void* proc = FindAPI_A(module, procedure);
    if (proc != &WinExec)
    {
        printf_s("Result:   %llX\n", (uint64)proc);
        printf_s("Expected: %llX\n", (uint64)(&WinExec));
        printf_s("WinExec address is incorrect\n");
        return false;
    }
    printf_s("WinExec: 0x%llX\n", (uint64)proc);
    return true;
}

static bool TestFindAPI_W()
{
    uint16* module    = L"kernel32.dll";
    byte*   procedure = "WinExec";

    void* proc = FindAPI_W(module, procedure);
    if (proc != &WinExec)
    {
        printf_s("Result:   %llX\n", (uint64)proc);
        printf_s("Expected: %llX\n", (uint64)(&WinExec));
        printf_s("WinExec address is incorrect\n");
        return false;
    }
    printf_s("WinExec: 0x%llX\n", (uint64)proc);
    return true;
}

static bool TestForwarded()
{
    HMODULE hModule = LoadLibraryA("kernel32.dll");
    if (hModule == NULL)
    {
        printf_s("failed to load kernel32.dll\n");
        return false;
    }
    void* closeState = GetProcAddress(hModule, "CloseState");

    byte* module    = "kernel32.dll";
    byte* procedure = "CloseState";
#ifdef _WIN64
    uint key = 0x6A6867C72D518853;
#elif _WIN32
    uint key = 0xCADE960B;
#endif
    uint modHash  = CalcModHash_A(module, key);
    uint procHash = CalcProcHash(procedure, key);

    void* proc = FindAPI_MH(modHash, procHash, key);
    if (proc != closeState)
    {
        printf_s("Result:   %llX\n", (uint64)proc);
        printf_s("Expected: %llX\n", (uint64)closeState);
        printf_s("CloseState address is incorrect\n");
        return false;
    }
    printf_s("CloseState: 0x%llX\n", (uint64)proc);
    return true;
}

static bool TestNotFound()
{
    void* proc = FindAPI_MH(0x1234, 0x5678, 0x1212);
    if (proc != NULL)
    {
        printf_s("still found\n");
        return false;
    }

    HMODULE hModule = LoadLibraryA("kernel32.dll");
    if (hModule == NULL)
    {
        printf_s("failed to load kernel32.dll\n");
        return false;
    }
    proc = FindAPI_MA(hModule, 0x5678, 0x1212);
    if (proc != NULL)
    {
        printf_s("still found\n");
        return false;
    }
    return true;
}

static bool TestNULLArgument()
{
    void* proc = FindAPI_MHL(NULL, 0x1234, 0x5678, 0x1212);
    if (proc != NULL)
    {
        printf_s("still found\n");
        return false;
    }

    PML* pml = GetDefaultPML();
    proc = FindAPI_MAL(pml, NULL, 0x5678, 0x1212);
    if (proc != NULL)
    {
        printf_s("still found\n");
        return false;
    }
    return true;
}

static bool TestCalcModHash32()
{
    byte*   module_a = "kernel32.dll";
    uint16* module_w = L"kernel32.dll";
    uint32  key      = 0xCADE960B;
    
    uint32 hash_a = CalcModHash32_A(module_a, key);
    uint32 hash_w = CalcModHash32_W(module_w, key);
    
    printf_s("hash: 0x%X\n", hash_a);
    if (hash_a != 0x42509A1C)
    {
        printf_s("hash is incorrect\n");
        return false;
    }
    if (hash_a != hash_w)
    {
        printf_s("hash is not equal\n");
        return false;
    }
    return true;
}

static bool TestCalcModHash64()
{
    byte*   module_a = "kernel32.dll";
    uint16* module_w = L"kernel32.dll";
    uint64  key      = 0x7A61A1C72F518C54;
    
    uint64 hash_a = CalcModHash64_A(module_a, key);
    uint64 hash_w = CalcModHash64_W(module_w, key);

    printf_s("hash: 0x%llX\n", hash_a);
    if (hash_a != 0x2A5175AD1A0CECBC)
    {
        printf_s("hash is incorrect\n");
        return false;
    }
    if (hash_a != hash_w)
    {
        printf_s("hash is not equal\n");
        return false;
    }
    return true;
}

static bool TestCalcProcHash32()
{
    byte*  proc = "WinExec";
    uint32 key  = 0xCADE960B;
    uint32 hash = CalcProcHash32(proc, key);
    
    printf_s("hash: 0x%X\n", hash);
    if (hash != 0x3CA3C21A)
    {
        printf_s("hash is incorrect\n");
        return false;
    }
    return true;
}

static bool TestCalcProcHash64()
{
    byte*  proc = "WinExec";
    uint64 key  = 0x7A61A1C72F518C54;
    uint64 hash = CalcProcHash64(proc, key);
    
    printf_s("hash: 0x%llX\n", hash);
    if (hash != 0x6596B31A1F68D830)
    {
        printf_s("hash is incorrect\n");
        return false;
    }
    return true;
}
