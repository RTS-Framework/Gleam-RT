#include <stdio.h>
#include "build.h"
#include "c_types.h"
#include "win_types.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "crypto.h"
#include "errno.h"
#include "mod_argument.h"
#include "runtime.h"
#include "test.h"

static void* loadInstance();
static void* calcEpilogue();

bool TestInitRuntime()
{
    Runtime_Opts opts = {
        .BootAddress         = NULL,
        .ImagePinningHash    = 0,
        .ShieldModuleHash    = 0,
        .ShieldEntryPoint    = 0,
        .EnableSecurityMode  = false,
        .DisableDetector     = false,
        .DisableSysmon       = false,
        .DisableWatchdog     = false,
        .NotEraseInstruction = true,
        .NotAdjustProtect    = false,
        .TrackCurrentThread  = false,
    };
#ifdef PIC_MODE
    typedef Runtime_M* (*InitRuntime_t)(Runtime_Opts* opts);
    InitRuntime_t initRuntime = loadInstance();
    runtime = initRuntime(&opts);
#else
    runtime = InitRuntime(&opts);
#endif // PIC_MODE
    if (runtime == NULL)
    {
        printf_s("failed to initialize runtime: 0x%X\n", GetLastErrno());
        panic(PANIC_UNREACHABLE_CODE);
        return false;
    }
    return true;
}

bool TestRuntime_Exit()
{
    errno errno = runtime->Core.Exit();
    if (errno != NO_ERROR)
    {
        printf_s("failed to exit runtime: 0x%X\n", errno);
        return false;
    }
    errno = GetLastErrno();
    if (errno != NO_ERROR)
    {
        printf_s("find last errno: 0x%X\n", errno);
        return false;
    }
    return true;
}

bool TestRuntime_Options()
{
    Runtime_Opts opts = {
        .BootAddress         = NULL,
        .ImagePinningHash    = 0,
        .ShieldModuleHash    = 0,
        .ShieldEntryPoint    = 0,
        .EnableSecurityMode  = false,
        .DisableDetector     = true,
        .DisableSysmon       = true,
        .DisableWatchdog     = true,
        .NotEraseInstruction = true,
        .NotAdjustProtect    = false,
        .TrackCurrentThread  = false,
    };
#ifdef PIC_MODE
    typedef Runtime_M* (*InitRuntime_t)(Runtime_Opts* opts);
    InitRuntime_t initRuntime = loadInstance();
    runtime = initRuntime(&opts);
#else
    runtime = InitRuntime(&opts);
#endif // PIC_MODE
    if (runtime == NULL)
    {
        printf_s("failed to initialize runtime: 0x%X\n", GetLastErrno());
        return false;
    }

    errno errno = runtime->Core.Sleep(1000);
    if (errno != NO_ERROR)
    {
        printf_s("failed to sleep: 0x%X\n", errno);
        return false;
    }

    errno = runtime->Core.Exit();
    if (errno != NO_ERROR)
    {
        printf_s("failed to exit runtime: 0x%X\n", errno);
        return false;
    }
    errno = GetLastErrno();
    if (errno != NO_ERROR)
    {
        printf_s("find last errno: 0x%X\n", errno);
        return false;
    }
    return true;
}

static void* loadInstance()
{
    VirtualAlloc_t VirtualAlloc = FindAPI_A("kernel32.dll", "VirtualAlloc");

    uintptr begin = (uintptr)(&InitRuntime);
    uintptr end   = (uintptr)(calcEpilogue());
    uintptr size  = end - begin;
    void* mem = VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (mem == NULL)
    {
        printf_s("failed to allocate memory: 0x%X\n", GetLastErrno());
        return NULL;
    }
    mem_copy(mem, (void*)begin, size);
    printf_s("Instance: 0x%zX\n", (uintptr)mem);
    return mem;
}

static void* calcEpilogue()
{
    uintptr stub = (uintptr)(&Argument_Stub);
    byte header[ARG_HEADER_SIZE];
    mem_init(header, sizeof(header));
    mem_copy(header, (byte*)stub, sizeof(header));
    byte* buf = header + ARG_CRYPTO_KEY_SIZE;
    uint  fsz = sizeof(uint16) + sizeof(uint32);
    XORBuf(buf, fsz, (byte*)stub, ARG_CRYPTO_KEY_SIZE);
    uint32 argsSize = *(uint32*)(header + ARG_OFFSET_ARGS_SIZE);
    return (void*)(stub + ARG_HEADER_SIZE + argsSize);
}
