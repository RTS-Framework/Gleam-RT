#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "hash_api.h"
#include "errno.h"
#include "ptr_table.h"
#include "mod_argument.h"
#include "shield.h"
#include "runtime.h"

// NOT using stdio is to ensure that no runtime instructions 
// are introduced to avoid compiler optimization link errors 
// that cause the extracted template to contain incorrect
// relative/absolute memory addresses.

static VirtualAlloc_t VirtualAlloc;
static VirtualFree_t  VirtualFree;
static LoadLibraryA_t LoadLibraryA;
static CreateFileA_t  CreateFileA;
static WriteFile_t    WriteFile;
static CloseHandle_t  CloseHandle;

typedef int (*printf_s_t)(const char* format, ...);
static printf_s_t printf_s;

bool testTemplate(bool erase);
bool saveTemplate();

static void init()
{
    VirtualAlloc = FindAPI_A("kernel32.dll", "VirtualAlloc");
    VirtualFree  = FindAPI_A("kernel32.dll", "VirtualFree");
    LoadLibraryA = FindAPI_A("kernel32.dll", "LoadLibraryA");
    CreateFileA  = FindAPI_A("kernel32.dll", "CreateFileA");
    WriteFile    = FindAPI_A("kernel32.dll", "WriteFile");
    CloseHandle  = FindAPI_A("kernel32.dll", "CloseHandle");

    HMODULE hModule = LoadLibraryA("msvcrt.dll");
    if (hModule == NULL)
    {
        return;
    }
    printf_s = FindAPI_A("msvcrt.dll", "printf_s");
}

#pragma comment(linker, "/ENTRY:EntryPoint")
int EntryPoint()
{
    init();
    if (!testTemplate(false))
    {
        return 1;
    }
    if (!saveTemplate())
    {
        return 2;
    }
    if (!testTemplate(true))
    {
        return 3;
    }
    printf_s("build template successfully\n");
    return 0;
}

bool testTemplate(bool erase)
{
    Runtime_Opts opts = {
        .BootAddress         = NULL,
        .ImagePinningHash    = 0,
        .ShieldModuleHash    = 0,
        .ShieldEntryPoint    = 0,
        .EnableSecurityMode  = false,
        .DisableDetector     = false,
        .DisableWatchdog     = false,
        .DisableSysmon       = false,
        .NotEraseInstruction = !erase,
        .NotAdjustProtect    = false,
        .TrackCurrentThread  = false,
    };
    Runtime_M* RuntimeM = InitRuntime(&opts);
    if (RuntimeM == NULL)
    {
        printf_s("failed to initialize runtime: 0x%X\n", GetLastErrno());
        return false;
    }
    printf_s("RuntimeM: 0x%llX\n", (uint64)RuntimeM);
    errno errno = RuntimeM->Core.Exit();
    if (errno != NO_ERROR)
    {
        printf_s("failed to exit runtime: 0x%X\n", errno);
        return false;
    }
    return true;
}

bool saveTemplate()
{
    uintptr begin = (uintptr)(&InitRuntime);
    uintptr end   = (uintptr)(&Argument_Stub);
    uintptr size  = end - begin;
    // copy instruction to new memory page
    LPVOID template = VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (template == NULL)
    {
        printf_s("failed to allocate memory: 0x%X\n", GetLastErrno());
        return false;
    }
    mem_copy(template, (void*)begin, size);

    // calculate the end address
    end = (uintptr)template + size;
    // initialize shield stub
    uintptr shieldStub = end - (SHIELD_STUB_SIZE + POINTER_STUB_SIZE + OPTION_STUB_SIZE);
    if (*(byte*)(shieldStub) != SHIELD_STUB_MAGIC)
    {
        printf_s("invalid runtime shield stub\n");
        return false;
    }
    mem_init((void*)(shieldStub+1), SHIELD_STUB_SIZE-1);
    // initialize pointer stub
    uintptr pointerStub = end - (POINTER_STUB_SIZE + OPTION_STUB_SIZE);
    if (*(byte*)(pointerStub) != POINTER_STUB_MAGIC)
    {
        printf_s("invalid runtime pointer stub\n");
        return false;
    }
    mem_init((void*)(pointerStub + 1), POINTER_STUB_SIZE - 1);
    // initialize option stub
    uintptr optionStub = end - OPTION_STUB_SIZE;
    if (*(byte*)(optionStub) != OPTION_STUB_MAGIC)
    {
        printf_s("invalid runtime option stub\n");
        return false;
    }
    mem_init((void*)(optionStub+1), OPTION_STUB_SIZE-1);

    // save template data to file
#ifdef _WIN64
    LPSTR path = "../dist/GleamRT_x64.bin";
#elif _WIN32
    LPSTR path = "../dist/GleamRT_x86.bin";
#endif
    HANDLE hFile = CreateFileA(
        path, GENERIC_WRITE, 0, NULL, 
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf_s("failed to create file: 0x%X\n", GetLastErrno());
        return false;
    }
    if (!WriteFile(hFile, template, (DWORD)size, NULL, NULL))
    {
        printf_s("failed to write template: 0x%X\n", GetLastErrno());
        return false;
    }

    // clean resource
    if (!CloseHandle(hFile))
    {
        printf_s("failed to close file: 0x%X\n", GetLastErrno());
        return false;
    }
    if (!VirtualFree(template, 0, MEM_RELEASE))
    {
        printf_s("failed to release memory: 0x%X\n", GetLastErrno());
        return false;
    }
    return true;
}
