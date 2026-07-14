#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "dll_psapi.h"
#include "lib_memory.h"
#include "hash_api.h"
#include "rel_addr.h"
#include "random.h"
#include "crypto.h"
#include "win_api.h"
#include "errno.h"
#include "context.h"
#include "layout.h"
#include "ptr_table.h"
#include "detector.h"
#include "debug.h"

// judgment threshold
#define JT_HAS_DEBUGGER       50
#define JT_HAS_MEMORY_SCANNER 10
#define JT_IN_SANDBOX         80
#define JT_IN_EMULATOR        70
#define JT_IN_VIRTUAL_MACHINE 70
#define JT_IS_ACCELERATED     80

// MUST be a multiple of 100.
#define MAX_SAFE_RANK 200

typedef struct {
    // store options
    bool DisableDetector;
    bool NotEraseInstruction;

    // process environment
    PEB* PEB;
    PML* PML;

    // API addresses
    GetTickCount_t        GetTickCount;
    FreeLibrary_t         FreeLibrary;
    VirtualFree_t         VirtualFree;
    ReleaseMutex_t        ReleaseMutex;
    WaitForSingleObject_t WaitForSingleObject;
    CloseHandle_t         CloseHandle;

    // lazy API addresses
    QueryWorkingSetEx_t QueryWorkingSetEx;

    // for detector memory scanner
    HMODULE hPsapi;
    LPVOID  memTrap;

    // protect data
    HANDLE hMutex;

    // most test items only run once,
    // but some items need detect loop.
    bool isDetected;

    bool PrevDebugged;
    bool StepOnMemTrap;

    uint16 HasDebugger;
    uint16 HasMemoryScanner;
    uint16 InSandbox;
    uint16 InEmulator;
    uint16 InVirtualMachine;
    uint16 IsAccelerated;
} Detector;

// methods for user
BOOL DT_Detect();
BOOL DT_GetStatus(DT_Status* status);

// methods for runtime
bool  DT_Lock();
bool  DT_Unlock();
errno DT_Stop();

static Detector* getDetectorPointer();

static bool initDetectorAPI(Detector* detector, Context* context);
static bool initDetectorEnvironment(Detector* detector, Context* context);
static void updateDetectorPointer(Detector* detector);
static void eraseDetectorMethods(Context* context);
static void cleanDetector(Detector* detector);

static bool detectOnceItem();
static bool detectLoopItem();
static bool detectDebugger();
static bool detectMemoryScanner();
static bool detectSandbox();
static bool detectEmulator();
static bool detectVirtualMachine();
static bool detectAccelerator();

Detector_M* InitDetector(Context* context)
{
    // set structure address
    uintptr addr = context->MainMemPage;
    uintptr detectorAddr = addr + LAYOUT_DT_STRUCT + RandUintN(addr, 128);
    uintptr methodAddr   = addr + LAYOUT_DT_MODULE + RandUintN(addr, 128);
    // allocate detector memory
    Detector* detector = (Detector*)detectorAddr;
    mem_init(detector, sizeof(Detector));
    // store options
    detector->DisableDetector     = context->DisableDetector;
    detector->NotEraseInstruction = context->NotEraseInstruction;
    // store process environment
    detector->PEB = context->PEB;
    detector->PML = context->PML;
    // initialize detector
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initDetectorAPI(detector, context))
        {
            errno = ERR_DETECTOR_INIT_API;
            break;
        }
        if (!initDetectorEnvironment(detector, context))
        {
            errno = ERR_DETECTOR_INIT_ENV;
            break;
        }
        break;
    }
    updateDetectorPointer(detector);
    eraseDetectorMethods(context);
    if (errno != NO_ERROR)
    {
        cleanDetector(detector);
        SetLastErrno(errno);
        return NULL;
    }
    // create methods for detector
    Detector_M* method = (Detector_M*)methodAddr;
    // methods for user
    method->Detect    = GetFuncAddr(&DT_Detect);
    method->GetStatus = GetFuncAddr(&DT_GetStatus);
    // methods for runtime
    method->Lock   = GetFuncAddr(&DT_Lock);
    method->Unlock = GetFuncAddr(&DT_Unlock);
    method->Stop   = GetFuncAddr(&DT_Stop);
    // data for sysmon
    method->hMutex = detector->hMutex;
    return method;
}

__declspec(noinline)
static bool initDetectorAPI(Detector* detector, Context* context)
{
    detector->GetTickCount        = context->GetTickCount;
    detector->FreeLibrary         = context->FreeLibrary;
    detector->VirtualFree         = context->VirtualFree;
    detector->ReleaseMutex        = context->ReleaseMutex;
    detector->WaitForSingleObject = context->WaitForSingleObject;
    detector->CloseHandle         = context->CloseHandle;
    return true;
}

__declspec(noinline)
static void updateDetectorPointer(Detector* detector)
{
    *(Detector**)(POINTER_OFFSET_DETECTOR) = detector;
}

__declspec(noinline)
static bool initDetectorEnvironment(Detector* detector, Context* context)
{
    // create mutex
    HANDLE hMutex = context->CreateMutexA(NULL, false, NAME_RT_DETECTOR_MUTEX);
    if (hMutex == NULL)
    {
        return false;
    }
    detector->hMutex = hMutex;
    // not try to find QueryWorkingSetEx if Detector is disabled
    if (context->DisableDetector)
    {
        return true;
    }
    // try to find QueryWorkingSetEx in kernel32.dll
    QueryWorkingSetEx_t QueryWorkingSetEx;
#ifdef _WIN64
    uint pHash = 0x712F73BAA281B7A7;
    uint hKey  = 0xC3107C1D3C0E7E7A;
#elif _WIN32
    uint pHash = 0x79D1EEA9;
    uint hKey  = 0x0F43DE10;
#endif
    QueryWorkingSetEx = context->FindAPI_MA(context->hKernel32, pHash, hKey);
    if (QueryWorkingSetEx == NULL)
    {
        // make sure psapi.dll is loaded for old Windows
        byte dllName[] = {
            'p'^0x3A, 's'^0x49, 'a'^0xC7, 'p'^0x19,
            'i'^0x3A, '.'^0x49, 'd'^0xC7, 'l'^0x19,
            'l'^0x3A, 000^0x49, 000^0xC7, 000^0x19,
        };
        byte key[] = { 0x3A, 0x49, 0xC7, 0x19 };
        XORBuffer(dllName, sizeof(dllName), key, sizeof(key));
        HMODULE hPsapi = context->LoadLibraryA(dllName);
        if (hPsapi == NULL)
        {
            return false;
        }
        // psapi.QueryWorkingSetEx is not exist on old Windows
    #ifdef _WIN64
        pHash = 0x75F48436269D0717;
        hKey  = 0x0DB79DD5BA6DDEBC;
    #elif _WIN32
        pHash = 0x06333B8D;
        hKey  = 0xE9D6A09C;
    #endif
        QueryWorkingSetEx = context->FindAPI_MA(hPsapi, pHash, hKey);
        if (QueryWorkingSetEx == NULL)
        {
            context->FreeLibrary(hPsapi);
        } else {
            detector->hPsapi = hPsapi;
        }
    }
    detector->QueryWorkingSetEx = QueryWorkingSetEx;
    // allocate trap memory page
    if (QueryWorkingSetEx != NULL)
    {
        SIZE_T size = (3 + RandUintN(0, 16)) * 1024;
        DWORD  type = MEM_COMMIT|MEM_RESERVE;
        LPVOID page = context->VirtualAlloc(NULL, size, type, PAGE_READWRITE);
        if (page == NULL)
        {
            return false;
        }
        detector->memTrap = page;
    }
    return true;
}

__declspec(noinline)
static void eraseDetectorMethods(Context* context)
{
    if (context->NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&initDetectorAPI));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseDetectorMethods));
    uintptr size  = end - begin;
    EraseInstruction((void*)begin, size);
}

__declspec(noinline)
static void cleanDetector(Detector* detector)
{
    if (detector->CloseHandle != NULL && detector->hMutex != NULL)
    {
        detector->CloseHandle(detector->hMutex);
    }
    if (detector->hPsapi != NULL)
    {
        detector->FreeLibrary(detector->hPsapi);
    }
    if (detector->VirtualFree != NULL && detector->memTrap != NULL)
    {
        detector->VirtualFree(detector->memTrap, 0, MEM_RELEASE);
    }
}

#pragma optimize("", off)
static Detector* getDetectorPointer()
{
    return *(Detector**)POINTER_OFFSET_DETECTOR;
}
#pragma optimize("", on)

__declspec(noinline)
BOOL DT_Detect()
{
    Detector* detector = getDetectorPointer();

    if (detector->DisableDetector)
    {
        return true;
    }

    if (!DT_Lock())
    {
        return false;
    }

    BOOL success = true;
    for (;;)
    {
        // items that need detect loop
        if (detector->isDetected)
        {
            success = detectLoopItem();
            break;
        }
        // common detect items
        success = detectOnceItem();
        detector->isDetected = true;
        break;
    }

    if (!DT_Unlock())
    {
        return false;
    }
    return success;
}

__declspec(noinline)
static bool detectOnceItem()
{
    bool success = true;
    typedef bool (*detection_t)();
    detection_t list[] = {
        GetFuncAddr(&detectDebugger),
        GetFuncAddr(&detectMemoryScanner),
        GetFuncAddr(&detectSandbox),
        GetFuncAddr(&detectEmulator),
        GetFuncAddr(&detectVirtualMachine),
        GetFuncAddr(&detectAccelerator),
    };
    int seq[arrlen(list)];
    RandSequence(seq, arrlen(seq));
    for (int i = 0; i < arrlen(seq); i++)
    {
        int idx = seq[i];
        if (!list[idx]())
        {
            success = false;
            break;
        }
    }
    return success;
}

__declspec(noinline)
static bool detectLoopItem()
{
    bool success = true;
    typedef bool (*detection_t)();
    detection_t list[] = {
        GetFuncAddr(&detectDebugger),
        GetFuncAddr(&detectMemoryScanner),
    };
    int seq[arrlen(list)];
    RandSequence(seq, arrlen(seq));
    for (int i = 0; i < arrlen(seq); i++)
    {
        int idx = seq[i];
        if (!list[idx]())
        {
            success = false;
            break;
        }
    }
    return success;
}

__declspec(noinline)
static bool detectDebugger()
{
    Detector* detector = getDetectorPointer();

    if (detector->PrevDebugged)
    {
        return true;
    }

    if (IsDebuggerPresent(detector->PEB))
    {
        detector->HasDebugger += 100;
        detector->PrevDebugged = true;
        return true;
    }
    return true;
}

__declspec(noinline)
static bool detectMemoryScanner()
{
    Detector* detector = getDetectorPointer();

    // check API is existed
    if (detector->QueryWorkingSetEx == NULL)
    {
        return true;
    }
    if (detector->StepOnMemTrap)
    {
        return true;
    }

    PSAPI_WORKING_SET_EX_INFORMATION info = {
        .VirtualAddress = detector->memTrap,
    };
    DWORD cb = sizeof(PSAPI_WORKING_SET_EX_INFORMATION);
    if (!detector->QueryWorkingSetEx(CURRENT_PROCESS, &info, cb))
    {
        return false;
    }
    if (info.VirtualAttributes.Valid)
    {
        detector->HasMemoryScanner += 100;
        detector->StepOnMemTrap = true;
    }
    return true;
}

__declspec(noinline)
static bool detectSandbox()
{
    Detector* detector = getDetectorPointer();

    // detect "SbieDLL.dll" is loaded
#ifdef _WIN64
    uint mHash = 0x708F4DF49237F0D1;
    uint hKey  = 0xF13802157DB9B2DB;
#elif _WIN32
    uint mHash = 0x08392D5C;
    uint hKey  = 0x81A86120;
#endif
    if (FindMod_MHL(detector->PML, mHash, hKey) != NULL)
    {
        detector->InSandbox += 100;
        return true;
    }
    return true;
}

__declspec(noinline)
static bool detectEmulator()
{
    Detector* detector = getDetectorPointer();

    return true;
}

__declspec(noinline)
static bool detectVirtualMachine()
{
    Detector* detector = getDetectorPointer();

    return true;
}

__declspec(noinline)
static bool detectAccelerator()
{
    Detector* detector = getDetectorPointer();

    return true;
}

__declspec(noinline)
BOOL DT_GetStatus(DT_Status* status)
{
    Detector* detector = getDetectorPointer();

    if (detector->DisableDetector)
    {
        status->IsEnabled = false;
        return true;
    }
    status->IsEnabled = true;

    if (!DT_Lock())
    {
        return false;
    }

    int32 total = 0;
    typedef struct {
        uint16 src; BOOL* dst; uint16 th;
    } item;
    item items[] = {
        { detector->HasDebugger,      &status->HasDebugger,      JT_HAS_DEBUGGER       },
        { detector->HasMemoryScanner, &status->HasMemoryScanner, JT_HAS_MEMORY_SCANNER },
        { detector->InSandbox,        &status->InSandbox,        JT_IN_SANDBOX         },
        { detector->InEmulator,       &status->InEmulator,       JT_IN_EMULATOR        },
        { detector->InVirtualMachine, &status->InVirtualMachine, JT_IN_VIRTUAL_MACHINE },
        { detector->IsAccelerated,    &status->IsAccelerated,    JT_IS_ACCELERATED     },
    };
    for (int i = 0; i < arrlen(items); i++)
    {
        item item = items[i];
        if (item.src >= item.th)
        {
            total += item.src;
            *item.dst = true;
        } else {
            *item.dst = false;
        }
    }

    int32 rank;
    if (total < MAX_SAFE_RANK)
    {
        rank = ((MAX_SAFE_RANK - total) / (MAX_SAFE_RANK / 100));
    } else {
        rank = 0;
    }
    status->SafeRank = rank;

    if (!DT_Unlock())
    {
        return false;
    }
    return true;
}

__declspec(noinline)
bool DT_Lock()
{
    Detector* detector = getDetectorPointer();

    DWORD event = detector->WaitForSingleObject(detector->hMutex, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
bool DT_Unlock()
{
    Detector* detector = getDetectorPointer();

    return detector->ReleaseMutex(detector->hMutex);
}

__declspec(noinline)
errno DT_Stop()
{
    Detector* detector = getDetectorPointer();

    errno errno = NO_ERROR;

    // close mutex
    if (!detector->CloseHandle(detector->hMutex) && errno == NO_ERROR)
    {
        errno = ERR_DETECTOR_CLOSE_MUTEX;
    }

    // free psapi.dll handle
    if (detector->hPsapi != NULL)
    {
        if (!detector->FreeLibrary(detector->hPsapi) && errno == NO_ERROR)
        {
            errno = ERR_DETECTOR_FREE_PSAPI;
        }
    }

    // free trap memory page
    if (detector->memTrap != NULL)
    {
        if (!detector->VirtualFree(detector->memTrap, 0, MEM_RELEASE))
        {
            if (errno == NO_ERROR)
            {
                errno = ERR_DETECTOR_FREE_TRAP_MEM;
            }
        }
    }
    return errno;
}
