#include "build.h"
#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "hash_api.h"
#include "list_md.h"
#include "rel_addr.h"
#include "random.h"
#include "crypto.h"
#include "errno.h"
#include "context.h"
#include "layout.h"
#include "ptr_table.h"
#include "mod_library.h"
#include "debug.h"

// since the essence of HMODULE is the memory address where
// the module is located, an address that cannot be assigned
// is used as a special placeholder.
#define MODULE_UNLOADED ((HMODULE)(0xFE))

typedef struct {
    HMODULE hModule;
    int64   counter;
    bool    locked;
} module;

typedef struct {
    // store options
    bool NotEraseInstruction;

    // API addresses
    LoadLibraryA_t             LoadLibraryA;
    LoadLibraryW_t             LoadLibraryW;
    LoadLibraryExA_t           LoadLibraryExA;
    LoadLibraryExW_t           LoadLibraryExW;
    FreeLibrary_t              FreeLibrary;
    FreeLibraryAndExitThread_t FreeLibraryAndExitThread;
    GetProcAddress_t           GetProcAddress;
    ReleaseMutex_t             ReleaseMutex;
    WaitForSingleObject_t      WaitForSingleObject;
    CloseHandle_t              CloseHandle;

    // runtime method
    rt_flush_api_cache_t RT_flush_api_cache;

    // protect data
    HANDLE hMutex;

    // store all modules info
    List Modules;
    byte ModulesKey[CRYPTO_KEY_SIZE];
    byte ModulesIV [CRYPTO_IV_SIZE];

    // record the number of call GetProcAddress.
    int64 NumProcedures;
} LibraryTracker;

// methods for API redirector
HMODULE LT_LoadLibraryA(LPCSTR lpLibFileName);
HMODULE LT_LoadLibraryW(LPCWSTR lpLibFileName);
HMODULE LT_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
HMODULE LT_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
BOOL    LT_FreeLibrary(HMODULE hLibModule);
void    LT_FreeLibraryAndExitThread(HMODULE hLibModule, DWORD dwExitCode);
FARPROC LT_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);

// methods for user
BOOL LT_LockModule(HMODULE hModule);
BOOL LT_UnlockModule(HMODULE hModule);
BOOL LT_GetStatus(LT_Status* status);
BOOL LT_FreeAllMu();

// methods for runtime
bool  LT_Lock();
bool  LT_Unlock();
errno LT_Encrypt();
errno LT_Decrypt();
errno LT_FreeAll();
errno LT_Clean();

static LibraryTracker* getTrackerPointer();

static bool initTrackerAPI(LibraryTracker* tracker, Context* context);
static bool initTrackerEnv(LibraryTracker* tracker, Context* context);
static void eraseTrackerMethod(Context* context);
static void cleanTrackerResource(LibraryTracker* tracker);
static void setTrackerPointer(LibraryTracker* tracker);

static bool isGleamRT_A(LPCSTR lpLibFileName);
static bool isGleamRT_W(LPCWSTR lpLibFileName);
static bool addModule(LibraryTracker* tracker, HMODULE hModule);
static bool delModule(LibraryTracker* tracker, HMODULE hModule);
static bool setModuleLocker(HMODULE hModule, bool lock);
static bool cleanModule(LibraryTracker* tracker, module* module);

LibraryTracker_M* InitLibraryTracker(Context* context)
{
    // set structure address
    uintptr addr = context->MainMemPage;
    uintptr trackerAddr = addr + LAYOUT_LT_STRUCT + RandUintN(addr, 128);
    uintptr moduleAddr  = addr + LAYOUT_LT_MODULE + RandUintN(addr, 128);
    // allocate tracker memory
    LibraryTracker* tracker = (LibraryTracker*)trackerAddr;
    mem_init(tracker, sizeof(LibraryTracker));
    // store options
    tracker->NotEraseInstruction = context->NotEraseInstruction;
    // initialize tracker
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initTrackerAPI(tracker, context))
        {
            errno = ERR_LIBRARY_INIT_API;
            break;
        }
        if (!initTrackerEnv(tracker, context))
        {
            errno = ERR_LIBRARY_INIT_ENV;
            break;
        }
        break;
    }
    eraseTrackerMethod(context);
    if (errno != NO_ERROR)
    {
        cleanTrackerResource(tracker);
        SetLastErrno(errno);
        return NULL;
    }
    setTrackerPointer(tracker);
    // create methods for tracker
    LibraryTracker_M* module = (LibraryTracker_M*)moduleAddr;
    // methods for API redirector
    module->LoadLibraryA             = GetFuncAddr(&LT_LoadLibraryA);
    module->LoadLibraryW             = GetFuncAddr(&LT_LoadLibraryW);
    module->LoadLibraryExA           = GetFuncAddr(&LT_LoadLibraryExA);
    module->LoadLibraryExW           = GetFuncAddr(&LT_LoadLibraryExW);
    module->FreeLibrary              = GetFuncAddr(&LT_FreeLibrary);
    module->FreeLibraryAndExitThread = GetFuncAddr(&LT_FreeLibraryAndExitThread);
    module->GetProcAddress           = GetFuncAddr(&LT_GetProcAddress);
    // methods for user
    module->LockModule   = GetFuncAddr(&LT_LockModule);
    module->UnlockModule = GetFuncAddr(&LT_UnlockModule);
    module->GetStatus    = GetFuncAddr(&LT_GetStatus);
    module->FreeAllMu    = GetFuncAddr(&LT_FreeAllMu);
    // methods for runtime
    module->Lock    = GetFuncAddr(&LT_Lock);
    module->Unlock  = GetFuncAddr(&LT_Unlock);
    module->Encrypt = GetFuncAddr(&LT_Encrypt);
    module->Decrypt = GetFuncAddr(&LT_Decrypt);
    module->FreeAll = GetFuncAddr(&LT_FreeAll);
    module->Clean   = GetFuncAddr(&LT_Clean);
    // data for sysmon
    module->hMutex = tracker->hMutex;
    return module;
}

__declspec(noinline)
static bool initTrackerAPI(LibraryTracker* tracker, Context* context)
{
    typedef struct {
        uint pHash; uint hKey; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x808C2FF22B2D9D78, 0xA68CAAECA3134551 }, // LoadLibraryW
        { 0xDFF7EC3F5E560E0A, 0x38F2FD039BF9CA9E }, // LoadLibraryExA
        { 0xDA92307872988E4D, 0xA7B682E33EBE53C4 }, // LoadLibraryExW
        { 0xCF29FE8E7DEFE800, 0x489EA897EC9610DD }, // FreeLibraryAndExitThread
    };
#elif _WIN32
    {
        { 0x9C61C8A0, 0x19146BC3 }, // LoadLibraryW
        { 0x734CC1DA, 0xEC23248B }, // LoadLibraryExA
        { 0xD1B55BF0, 0xA20E3043 }, // LoadLibraryExW
        { 0xF5407AE5, 0xD65FEC05 }, // FreeLibraryAndExitThread
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        winapi item = list[i];
        void*  proc = context->FindAPI_MA(context->hKernel32, item.pHash, item.hKey);
        if (proc == NULL)
        {
            return false;
        }
        list[i].proc = proc;
    }
    tracker->LoadLibraryW             = list[0].proc;
    tracker->LoadLibraryExA           = list[1].proc;
    tracker->LoadLibraryExW           = list[2].proc;
    tracker->FreeLibraryAndExitThread = list[3].proc;

    tracker->LoadLibraryA        = context->LoadLibraryA;
    tracker->FreeLibrary         = context->FreeLibrary;
    tracker->GetProcAddress      = context->GetProcAddress;
    tracker->ReleaseMutex        = context->ReleaseMutex;
    tracker->WaitForSingleObject = context->WaitForSingleObject;
    tracker->CloseHandle         = context->CloseHandle;
    return true;
}

__declspec(noinline)
static bool initTrackerEnv(LibraryTracker* tracker, Context* context)
{
    // create mutex
    HANDLE hMutex = context->CreateMutexA(NULL, false, NAME_RT_LT_MUTEX_GLOBAL);
    if (hMutex == NULL)
    {
        return false;
    }
    tracker->hMutex = hMutex;
    // initialize module list
    List_Ctx ctx = {
        .malloc  = context->malloc,
        .realloc = context->realloc,
        .free    = context->free,
    };
    List_Init(&tracker->Modules, &ctx, sizeof(module));
    // set crypto context data
    RandBuffer(tracker->ModulesKey, CRYPTO_KEY_SIZE);
    RandBuffer(tracker->ModulesIV, CRYPTO_IV_SIZE);
    // copy runtime method
    tracker->RT_flush_api_cache = context->flush_api_cache;
    return true;
}

__declspec(noinline)
static void eraseTrackerMethod(Context* context)
{
    if (context->NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&initTrackerAPI));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseTrackerMethod));
    uintptr size  = end - begin;
    EraseInstruction((void*)begin, size);
}

__declspec(noinline)
static void cleanTrackerResource(LibraryTracker* tracker)
{
    if (tracker->CloseHandle != NULL && tracker->hMutex != NULL)
    {
        tracker->CloseHandle(tracker->hMutex);
    }
    List_Free(&tracker->Modules);
}

__declspec(noinline)
static void setTrackerPointer(LibraryTracker* tracker)
{
    *(LibraryTracker**)(POINTER_OFFSET_LIBRARY_TRACKER) = tracker;
}

#pragma optimize("", off)
static LibraryTracker* getTrackerPointer()
{
    return *(LibraryTracker**)POINTER_OFFSET_LIBRARY_TRACKER;
}
#pragma optimize("", on)

__declspec(noinline)
HMODULE LT_LoadLibraryA(LPCSTR lpLibFileName)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (isGleamRT_A(lpLibFileName))
    {
        return HMODULE_GLEAM_RT;
    }

    if (!LT_Lock())
    {
        return NULL;
    }

    HMODULE hModule;

    bool success = false;
    for (;;)
    {
        hModule = tracker->LoadLibraryA(lpLibFileName);
        if (hModule == NULL)
        {
            break;
        }
        if (!addModule(tracker, hModule))
        {
            break;
        }
        success = true;
        break;
    }

    dbg_log("[library]", "LoadLibraryA: %s 0x%zX", lpLibFileName, hModule);

    if (!LT_Unlock())
    {
        if (success)
        {
            tracker->FreeLibrary(hModule);
        }
        return NULL;
    }
    if (!success)
    {
        return NULL;
    }
    return hModule;
}

__declspec(noinline)
HMODULE LT_LoadLibraryW(LPCWSTR lpLibFileName)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (isGleamRT_W(lpLibFileName))
    {
        return HMODULE_GLEAM_RT;
    }

    if (!LT_Lock())
    {
        return NULL;
    }

    HMODULE hModule;

    bool success = false;
    for (;;)
    {
        hModule = tracker->LoadLibraryW(lpLibFileName);
        if (hModule == NULL)
        {
            break;
        }
        if (!addModule(tracker, hModule))
        {
            break;
        }
        success = true;
        break;
    }

    dbg_log("[library]", "LoadLibraryW: %ls 0x%zX", lpLibFileName, hModule);

    if (!LT_Unlock())
    {
        if (success)
        {
            tracker->FreeLibrary(hModule);
        }
        return NULL;
    }
    if (!success)
    {
        return NULL;
    }
    return hModule;
}

__declspec(noinline)
HMODULE LT_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (isGleamRT_A(lpLibFileName))
    {
        return HMODULE_GLEAM_RT;
    }

    if (!LT_Lock())
    {
        return NULL;
    }

    HMODULE hModule;

    bool success = false;
    for (;;)
    {
        hModule = tracker->LoadLibraryExA(lpLibFileName, hFile, dwFlags);
        if (hModule == NULL)
        {
            break;
        }
        if (!addModule(tracker, hModule))
        {
            break;
        }
        success = true;
        break;
    }

    dbg_log("[library]", "LoadLibraryExA: %s 0x%zX", lpLibFileName, hModule);

    if (!LT_Unlock())
    {
        if (success)
        {
            tracker->FreeLibrary(hModule);
        }
        return NULL;
    }
    if (!success)
    {
        return NULL;
    }
    return hModule;
}

__declspec(noinline)
HMODULE LT_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (isGleamRT_W(lpLibFileName))
    {
        return HMODULE_GLEAM_RT;
    }

    if (!LT_Lock())
    {
        return NULL;
    }

    HMODULE hModule;

    bool success = false;
    for (;;)
    {
        hModule = tracker->LoadLibraryExW(lpLibFileName, hFile, dwFlags);
        if (hModule == NULL)
        {
            break;
        }
        if (!addModule(tracker, hModule))
        {
            break;
        }
        success = true;
        break;
    }

    dbg_log("[library]", "LoadLibraryExW: %ls 0x%zX", lpLibFileName, hModule);

    if (!LT_Unlock())
    {
        if (success)
        {
            tracker->FreeLibrary(hModule);
        }
        return NULL;
    }
    if (!success)
    {
        return NULL;
    }
    return hModule;
}

__declspec(noinline)
BOOL LT_FreeLibrary(HMODULE hLibModule)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (hLibModule == HMODULE_GLEAM_RT)
    {
        return true;
    }

    if (!LT_Lock())
    {
        return false;
    }

    BOOL success = false;
    for (;;)
    {
        if (!tracker->FreeLibrary(hLibModule))
        {
            break;
        }
        if (!delModule(tracker, hLibModule))
        {
            break;
        }
        if (!tracker->RT_flush_api_cache())
        {
            SetLastErrno(ERR_LIBRARY_FLUSH_CACHE);
            break;
        }
        success = true;
        break;
    }

    dbg_log("[library]", "FreeLibrary: 0x%zX", hLibModule);

    if (!LT_Unlock())
    {
        return false;
    }
    return success;
}

__declspec(noinline)
void LT_FreeLibraryAndExitThread(HMODULE hLibModule, DWORD dwExitCode)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (hLibModule == HMODULE_GLEAM_RT)
    {
        return;
    }

    if (!LT_Lock())
    {
        return;
    }

    delModule(tracker, hLibModule);
    tracker->RT_flush_api_cache();
    dbg_log("[library]", "FreeLibraryAndExitThread: 0x%zX", hLibModule);

    if (!LT_Unlock())
    {
        return;
    }

    // TODO clean thread before exit thread
    tracker->FreeLibraryAndExitThread(hLibModule, dwExitCode);
}

// disable optimize for use call, NOT jmp to tracker->GetProcAddress.
#pragma optimize("", off)
FARPROC LT_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (!LT_Lock())
    {
        return NULL;
    }

    FARPROC proc;
    for (;;)
    {
        proc = tracker->GetProcAddress(hModule, lpProcName);
        if (proc == NULL)
        {
            break;
        }
        tracker->NumProcedures++;
        break;
    }

    if (lpProcName > (LPCSTR)(0xFFFF))
    {
        dbg_log("[library]", "GetProcAddress: 0x%zX, %s", hModule, lpProcName);
    } else {
        dbg_log("[library]", "GetProcAddress: 0x%zX, %d", hModule, (uint16)lpProcName);
    }

    if (!LT_Unlock())
    {
        return NULL;
    }
    return proc;
}
#pragma optimize("", on)

__declspec(noinline)
static bool isGleamRT_A(LPCSTR lpLibFileName)
{
    uint32 key  = 0xFFFFFFFF;
    uint32 hash = 0x65DF1F0C;
    return CalcModHash32_A((byte*)lpLibFileName, key) == hash;
}

__declspec(noinline)
static bool isGleamRT_W(LPCWSTR lpLibFileName)
{
    uint32 key  = 0xFFFFFFFF;
    uint32 hash = 0x65DF1F0C;
    return CalcModHash32_W((uint16*)lpLibFileName, key) == hash;
}

static bool addModule(LibraryTracker* tracker, HMODULE hModule)
{
    if (hModule == NULL)
    {
        return false;
    }
    List* modules = &tracker->Modules;
    // check this module is already exists
    module mod = {
        .hModule = hModule,
        .counter = 0,
        .locked  = false,
    };
    uint index;
    if (List_Find(modules, &mod, sizeof(mod.hModule), &index))
    {
        module* module = List_Get(modules, index);
        module->counter++;
        return true;
    }
    // if it is not exist, add new item
    mod.counter = 1;
    if (!List_Insert(modules, &mod))
    {
        tracker->FreeLibrary(hModule);
        return false;
    }
    return true;
}

static bool delModule(LibraryTracker* tracker, HMODULE hModule)
{
    if (hModule == NULL)
    {
        return false;
    }
    List* modules = &tracker->Modules;
    // search module and decrease counter
    module mod = {
        .hModule = hModule,
    };
    uint index;
    if (!List_Find(modules, &mod, sizeof(mod.hModule), &index))
    {
        return false;
    }
    module* module = List_Get(modules, index);
    module->counter--;
    // mark it is deleted and reserve space
    // for free the loaded DLL in reverse order
    if (module->counter == 0)
    {
        module->hModule = MODULE_UNLOADED;
    }
    return true;
}

__declspec(noinline)
BOOL LT_LockModule(HMODULE hModule)
{
    bool success = setModuleLocker(hModule, true);
    dbg_log("[library]", "lock module: 0x%zX", hModule);
    return success;
}

__declspec(noinline)
BOOL LT_UnlockModule(HMODULE hModule)
{
    bool success = setModuleLocker(hModule, false);
    dbg_log("[library]", "unlock module: 0x%zX", hModule);
    return success;
}

__declspec(noinline)
static bool setModuleLocker(HMODULE hModule, bool lock)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (!LT_Lock())
    {
        return false;
    }

    bool success = false;
    for (;;)
    {
        List* modules = &tracker->Modules;
        // search module list
        module mod = {
            .hModule = hModule,
        };
        uint index;
        if (!List_Find(modules, &mod, sizeof(mod.hModule), &index))
        {
            break;
        }
        // set module locker
        module* module = List_Get(modules, index);
        module->locked = lock;
        success = true;
        break;
    }

    if (!LT_Unlock())
    {
        return false;
    }
    return success;
}

__declspec(noinline)
BOOL LT_GetStatus(LT_Status* status)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (!LT_Lock())
    {
        return false;
    }

    // count the number of the tracked modules
    List* modules = &tracker->Modules;
    int64 numMods = 0;
    uint len = modules->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        module* module = List_Get(modules, idx);
        if (module->hModule == NULL)
        {
            continue;
        }
        if (module->hModule != MODULE_UNLOADED)
        {
            numMods++;
        }
        num++;
    }
    // count the number of the call GetProcAddress
    int64 numProcs = tracker->NumProcedures;

    if (!LT_Unlock())
    {
        return false;
    }

    status->NumModules    = numMods;
    status->NumProcedures = numProcs;
    return true;
}

__declspec(noinline)
BOOL LT_FreeAllMu()
{
    LibraryTracker* tracker = getTrackerPointer();

    if (!LT_Lock())
    {
        return false;
    }

    errno errno = NO_ERROR;
    for (;;)
    {
        errno = LT_FreeAll();
        if (errno != NO_ERROR)
        {
            break;
        }
        if (!tracker->RT_flush_api_cache())
        {
            errno = ERR_LIBRARY_FLUSH_CACHE;
            break;
        }
        break;
    }

    if (!LT_Unlock())
    {
        return false;
    }

    dbg_log("[library]", "FreeAll has been called");

    if (errno != NO_ERROR)
    {
        SetLastErrno(errno);
        return false;
    }
    return true;
}

__declspec(noinline)
bool LT_Lock()
{
    LibraryTracker* tracker = getTrackerPointer();

    DWORD event = tracker->WaitForSingleObject(tracker->hMutex, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
bool LT_Unlock()
{
    LibraryTracker* tracker = getTrackerPointer();

    return tracker->ReleaseMutex(tracker->hMutex);
}

__declspec(noinline)
errno LT_Encrypt()
{
    LibraryTracker* tracker = getTrackerPointer();

    List* list = &tracker->Modules;
    byte* key  = tracker->ModulesKey;
    byte* iv   = tracker->ModulesIV;
    RandBuffer(key, CRYPTO_KEY_SIZE);
    RandBuffer(iv, CRYPTO_IV_SIZE);
    EncryptBuffer(list->Data, List_Size(list), key, iv);
    return NO_ERROR;
}

__declspec(noinline)
errno LT_Decrypt()
{
    LibraryTracker* tracker = getTrackerPointer();

    List* list = &tracker->Modules;
    byte* key  = tracker->ModulesKey;
    byte* iv   = tracker->ModulesIV;
    DecryptBuffer(list->Data, List_Size(list), key, iv);

    dbg_log("[library]", "modules:    %zu", list->Len);
    dbg_log("[library]", "procedures: %zu", tracker->NumProcedures);
    return NO_ERROR;
}

__declspec(noinline)
errno LT_FreeAll()
{
    LibraryTracker* tracker = getTrackerPointer();

    List* modules = &tracker->Modules;
    errno errno   = NO_ERROR;

    // free the loaded DLL in reverse order
    uint len = modules->Len;
    uint idx = modules->Last;
    for (uint num = 0; num < len; idx--)
    {
        module* module = List_Get(modules, idx);
        if (module->hModule == NULL)
        {
            continue;
        }
        // skip locked module
        if (module->locked)
        {
            num++;
            continue;
        }
        if (module->hModule != MODULE_UNLOADED)
        {
            if (!cleanModule(tracker, module))
            {
                errno = ERR_LIBRARY_CLEAN_MODULE;
            }
        }
        if (!List_Delete(modules, idx))
        {
            errno = ERR_LIBRARY_DELETE_MODULE;
        }
        num++;
    }

    dbg_log("[library]", "modules:    %zu", modules->Len);
    dbg_log("[library]", "procedures: %zu", tracker->NumProcedures);
    return errno;
}

__declspec(noinline)
errno LT_Clean()
{
    LibraryTracker* tracker = getTrackerPointer();

    List* modules = &tracker->Modules;
    errno errno   = NO_ERROR;

    // free the loaded DLL in reverse order
    uint len = modules->Len;
    uint idx = modules->Last;
    for (uint num = 0; num < len; idx--)
    {
        module* module = List_Get(modules, idx);
        if (module->hModule == NULL)
        {
            continue;
        }
        if (module->hModule != MODULE_UNLOADED)
        {
            if (!cleanModule(tracker, module))
            {
                errno = ERR_LIBRARY_CLEAN_MODULE;
            }
        }
        num++;
    }

    // clean module list
    RandBuffer(modules->Data, List_Size(modules));
    if (!List_Free(modules) && errno == NO_ERROR)
    {
        errno = ERR_LIBRARY_FREE_LIST;
    }

    // close mutex
    if (!tracker->CloseHandle(tracker->hMutex) && errno == NO_ERROR)
    {
        errno = ERR_LIBRARY_CLOSE_MUTEX;
    }

    dbg_log("[library]", "modules:    %zu", modules->Len);
    dbg_log("[library]", "procedures: %zu", tracker->NumProcedures);
    return errno;
}

static bool cleanModule(LibraryTracker* tracker, module* module)
{
    int64 num = module->counter;
    for (int64 i = 0; i < num; i++)
    {
        if (!tracker->FreeLibrary(module->hModule))
        {
            return false;
        }
    }
    return true;
}
