#include "build.h"
#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "hash_api.h"
#include "hash_mod.h"
#include "rel_addr.h"
#include "random.h"
#include "crypto.h"
#include "errno.h"
#include "context.h"
#include "layout.h"
#include "ptr_table.h"
#include "shield.h"
#include "debug.h"

#define METHOD_SLEEP 1
#define METHOD_STOP  2

typedef struct {
    uintptr Method;

    VirtualProtect_t      VirtualProtect;
    WaitForSingleObject_t WaitForSingleObject;
    void*                 Reserved;

    void* CriticalAddr;
    uint  CriticalSize;
    void* DecoyAddr;
    uint  DecoySize;

    void*  Shelter;
    HANDLE Timer;
} Sleep_Args;

typedef struct {
    uintptr Method;

    VirtualProtect_t VirtualProtect;
    VirtualFree_t    VirtualFree;
    ExitThread_t     ExitThread;

    void* CriticalAddr;
    uint  CriticalSize;
    void* DecoyAddr;
    uint  DecoySize;

    uint ExitCode;
} Stop_Args;

typedef struct {
    // store option
    bool NotEraseInstruction;
    bool NotAdjustProtect;

    VirtualFree_t          VirtualFree;
    VirtualProtect_t       VirtualProtect;
    ExitThread_t           ExitThread;
    SetWaitableTimer_t     SetWaitableTimer;
    WaitForSingleObject_t  WaitForSingleObject;
    CloseHandle_t          CloseHandle;

    // runtime data
    void* MainMemPage;
    void* InstAddr;
    uint  InstSize;

    // about decoy and shelter
    void* DecoyAddr;
    uint  DecoySize;
    void* Shelter;

    // shield entry point
    void* EntryPoint;

    // allocated shield address
    void* ShieldPage;

    // for sleep
    HANDLE Timer;

    SD_Status status;
} Shield;

// methods for user
BOOL SD_GetStatus(SD_Status* status);

// methods for runtime
errno SD_Sleep(uint32 milliseconds);
void  SD_Stop(uint32 code);
errno SD_Clean();

static Shield* getShieldPointer();

static bool  initShieldAPI(Shield* shield, Context* context);
static errno initShieldEnv(Shield* shield, Context* context);
static void  eraseShieldMethod(Context* context);
static void  cleanShieldResource(Shield* shield);
static void  setShieldPointer(Shield* shield);

static void unshuffle(byte* data, uint32 size, uint64 seed);

static errno sd_clean(Shield* shield);

Shield_M* InitShield(Context* context)
{
    // set structure address
    uintptr addr = context->MainMemPage;
    uintptr shieldAddr = addr + LAYOUT_SD_STRUCT + RandUintN(0, 128);
    uintptr methodAddr = addr + LAYOUT_SD_METHOD + RandUintN(0, 128);
    // allocate shield memory
    Shield* shield = (Shield*)shieldAddr;
    mem_init(shield, sizeof(Shield));
    // store options
    shield->NotEraseInstruction = context->NotEraseInstruction;
    shield->NotAdjustProtect    = context->NotAdjustProtect;
    // initialize shield
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initShieldAPI(shield, context))
        {
            errno = ERR_SHIELD_INIT_API;
            break;
        }
        errno = initShieldEnv(shield, context);
        if (errno != NO_ERROR)
        {
            break;
        }
        break;
    }
    eraseShieldMethod(context);
    if (errno != NO_ERROR)
    {
        cleanShieldResource(shield);
        SetLastErrno(errno);
        return NULL;
    }
    setShieldPointer(shield);
    // create methods for shield
    Shield_M* method = (Shield_M*)methodAddr;
    // methods for user
    method->GetStatus = GetFuncAddr(&SD_GetStatus);
    // methods for runtime
    method->Sleep  = GetFuncAddr(&SD_Sleep);
    method->Stop   = GetFuncAddr(&SD_Stop);
    method->Clean  = GetFuncAddr(&SD_Clean);
    return method;
}

__declspec(noinline)
static bool initShieldAPI(Shield* shield, Context* context)
{
    // get original API address
    typedef struct {
        uint pHash; uint hKey; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x9ED80CDB7C8DC7CB, 0x93DEFC8B369AEB09 }, // VirtualFree
        { 0x07847A7F31B555AA, 0xE8CD656DB309997E }, // VirtualProtect
        { 0x47310D64BDB74A5A, 0xB770E3DCC3F639EF }, // ExitThread
        { 0x7084089B2EECD03E, 0x859DED82D1FEBB27 }, // WaitForSingleObject
    };
#elif _WIN32
    {
        { 0x6E1ADA58, 0xF607BBCE }, // VirtualFree
        { 0xC5560D17, 0xB641E477 }, // VirtualProtect
        { 0xCE1AB90A, 0x1CA2C5D8 }, // ExitThread
        { 0xB1FF31C3, 0xA11C1DDA }, // WaitForSingleObject
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        winapi item = list[i];
        void*  proc = FindAPI_MAL(context->PML, context->hKernel32, item.pHash, item.hKey);
        if (proc == NULL)
        {
            return false;
        }
        list[i].proc = proc;
    }
    shield->VirtualFree         = list[0x00].proc;
    shield->VirtualProtect      = list[0x01].proc;
    shield->ExitThread          = list[0x02].proc;
    shield->WaitForSingleObject = list[0x03].proc;

    // if the shield stub is NOT pre-injected, use copy from context
    if (context->ShieldModuleHash == 0)
    {
        shield->VirtualFree    = context->VirtualFree;
        shield->VirtualProtect = context->VirtualProtect;
        shield->ExitThread     = context->ExitThread;
    }

    // force use copy from context when security mode is enabled
    if (context->EnableSecurityMode)
    {
        shield->VirtualProtect = context->VirtualProtect;
    }

    // copy from context
    shield->SetWaitableTimer = context->SetWaitableTimer;
    shield->CloseHandle      = context->CloseHandle;

    // erase data in the large stack
    mem_init(list, sizeof(list));
    return true;
}

__declspec(noinline)
static errno initShieldEnv(Shield* shield, Context* context)
{
    // get stub address
    uintptr stub = (uintptr)(GetFuncAddr(&Shield_Stub));
    // prepare xor key
    uint64 seed = *(uint64*)(stub + 1);
    uint16 off  = 1 + sizeof(uint64);
    // get shield
    uint16 shieldSize = *(uint16*)(stub + off);
    off += sizeof(uint16);
    byte* shieldInst = (byte*)(stub + off);
    off += shieldSize;
    // get decoy
    uint16 decoySize = *(uint16*)(stub + off);
    off += sizeof(uint16);
    byte* decoyInst = (byte*)(stub + off);
    // check decoy size is enough
    if (context->EnableSecurityMode)
    {
        if (decoySize < SHIELD_SEC_MIN_DECOY_SIZE)
        {
            return ERR_SHIELD_DECOY_SIZE;
        }
    }
    // save status
    shield->DecoyAddr = decoyInst;
    shield->DecoySize = decoySize;

    // deploy shield
    #define SHIELD_TARGET_MEM_ADDRESS 1
    #define SHIELD_TARGET_SHIELD_STUB 2
    #define SHIELD_TARGET_EXE_MODULE  3
    #define SHIELD_TARGET_DLL_MODULE  4
    int target;
    if (context->ShieldMemAddress != 0)
    {
        target = SHIELD_TARGET_MEM_ADDRESS;
    } else if (context->ShieldModuleHash == 0) {
        target = SHIELD_TARGET_SHIELD_STUB;
    } else if (context->ShieldModuleHash == SHIELD_MAIN_MODULE) {
        target = SHIELD_TARGET_EXE_MODULE;
    } else {
        target = SHIELD_TARGET_DLL_MODULE;
    }
    switch (target)
    {
    case SHIELD_TARGET_MEM_ADDRESS:
        shield->status.EntryPoint  = (void*)((uintptr)(context->ShieldMemAddress));
        shield->status.BaseAddress = 0;
        shield->status.Source      = SHIELD_SRC_EXTERNAL;
        break;
    case SHIELD_TARGET_SHIELD_STUB:
        // allocate RWX memory page for shield
        SIZE_T size = shieldSize + (2 + RandUintN(0, 8)) * 1024;
        DWORD  type = MEM_COMMIT|MEM_RESERVE;
        LPVOID addr = context->VirtualAlloc(NULL, size, type, PAGE_EXECUTE_READWRITE);
        if (addr == NULL)
        {
            return ERR_SHIELD_ALLOC_SHIELD;
        }
        shield->ShieldPage = addr;
        // copy shield to memory page
        void* entryPoint = (void*)((uintptr)addr + (8 + RandUintN(0, 96)) * 16);
        mem_copy(entryPoint, shieldInst, shieldSize);
        unshuffle(entryPoint, shieldSize, seed);
        shield->EntryPoint = entryPoint;
        // set status
        shield->status.EntryPoint  = entryPoint;
        shield->status.BaseAddress = addr;
        shield->status.Source      = SHIELD_SRC_SHIELD_STUB;
        break;
    case SHIELD_TARGET_EXE_MODULE:
        uintptr base = (uintptr)(context->ImageBase);
        uintptr sep  = (uintptr)(context->ShieldEntryPoint);
        // set status
        shield->status.EntryPoint  = (void*)(base + sep);
        shield->status.BaseAddress = context->ImageBase;
        shield->status.Source      = SHIELD_SRC_PRE_INJECTED;
        break;
    case SHIELD_TARGET_DLL_MODULE:
        uintptr imageBase = 0;
        // find the target module and calculate
        // the pre-injected shield entry point
        PML* pml = context->PML;
        LIST_ENTRY* head = &pml->Links;
        for (LIST_ENTRY* link = head->Flink; link != head; link = link->Flink)
        {
            PML* entry = (PML*)((uintptr)(link)-offsetof(PML, Links));
            UNICODE_STRING name = entry->BaseName;
            if (HashMod(name.Buffer, name.Length) != context->ShieldModuleHash)
            {
                continue;
            }
            imageBase = (uintptr)(entry->ImageBase);
            break;
        }
        if (imageBase == 0)
        {
            return ERR_SHIELD_MODULE_NOT_FOUND;
        }
        uintptr offset = (uintptr)(context->ShieldEntryPoint);
        // set status
        shield->status.EntryPoint  = (void*)(imageBase + offset);
        shield->status.BaseAddress = (void*)(imageBase);
        shield->status.Source      = SHIELD_SRC_PRE_INJECTED;
        break;
    }

    // prepare shelter for save instance
    SIZE_T size = context->InstSize + (2 + RandUintN(0, 64)) * 4096;
    DWORD  type = MEM_COMMIT|MEM_RESERVE;
    LPVOID addr = context->VirtualAlloc(NULL, size, type, PAGE_READWRITE);
    if (addr == NULL)
    {
        return ERR_SHIELD_ALLOC_SHELTER;
    }
    shield->Shelter = addr;

    // prepare waitable timer
    HANDLE hTimer = context->CreateWaitableTimerA(NULL, false, NAME_RT_SD_TIMER_SLEEP);
    if (hTimer == NULL)
    {
        return ERR_SHIELD_CREATE_TIMER;
    }
    shield->Timer = hTimer;

    // erase shield in stub after deploy
    if (!context->NotEraseInstruction)
    {
        uint sz = 1 + sizeof(uint64) + sizeof(uint16) + shieldSize + sizeof(uint16);
        EraseInstruction((void*)stub, sz);
    }

    // TODO need add a new option? for control adjust protect about runtime body
    // prepare VirtualProtect address
    if (context->NotAdjustProtect)
    {
        shield->VirtualProtect = NULL;
    }

    // copy runtime data
    shield->MainMemPage = (void*)(context->MainMemPage);
    shield->InstAddr    = (void*)(context->Prologue);
    shield->InstSize    = alignup(context->InstSize, sizeof(uint));
    return NO_ERROR;
}

__declspec(noinline)
static void eraseShieldMethod(Context* context)
{
    if (context->NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&initShieldAPI));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseShieldMethod));
    uintptr size  = end - begin;
    EraseInstruction((void*)begin, size);
}

__declspec(noinline)
static void cleanShieldResource(Shield* shield)
{
    if (shield->Shelter != NULL)
    {
        shield->VirtualFree(shield->Shelter, 0, MEM_RELEASE);
    }
    if (shield->ShieldPage != NULL)
    {
        shield->VirtualFree(shield->ShieldPage, 0, MEM_RELEASE);
    }
    if (shield->Timer != NULL)
    {
        shield->CloseHandle(shield->Timer);
    }
}

// this method will be linked to another modules, so must move
// it after eraseShieldMethod.

__declspec(noinline)
static void unshuffle(byte* data, uint32 size, uint64 seed)
{
    // advance to the final seed
    for (uint32 i = size - 1; i > 0; i--)
    {
        seed = XORShift64(seed);
    }
    // reverse shuffle
    for (uint64 i = 1; i < size; i++)
    {
        seed = ReverseXORShift64(seed);
        uint j = (uint)(seed % (i + 1));
        byte t = data[i];
        data[i] = data[j];
        data[j] = t;
    }
}

__declspec(noinline)
static void setShieldPointer(Shield* shield)
{
    *(Shield**)(POINTER_OFFSET_SHIELD) = shield;
}

__declspec(noinline)
static Shield* getShieldPointer()
{
    return *(Shield**)POINTER_OFFSET_SHIELD;
}

__declspec(noinline)
BOOL SD_GetStatus(SD_Status* status)
{
    Shield* shield = getShieldPointer();

    *status = shield->status;
    return true;
}

__declspec(noinline)
errno SD_Sleep(uint32 milliseconds)
{
    Shield* shield = getShieldPointer();

    // prepare waitable timer
    int64 dueTime = -((int64)milliseconds * 1000 * 10);
    if (!shield->SetWaitableTimer(shield->Timer, &dueTime, 0, NULL, NULL, false))
    {
        return ERR_SHIELD_SET_TIMER;
    }

    // build sleep arguments
    Sleep_Args args = {
        .Method = METHOD_SLEEP,

        .VirtualProtect      = shield->VirtualProtect,
        .WaitForSingleObject = shield->WaitForSingleObject,

        .CriticalAddr = shield->InstAddr,
        .CriticalSize = shield->InstSize,
        .DecoyAddr    = shield->DecoyAddr,
        .DecoySize    = shield->DecoySize,

        .Shelter = shield->Shelter,
        .Timer   = shield->Timer,
    };

    // save entry point before encrypt
    typedef void (*Shield_Sleep_t)(Sleep_Args* args);
    Shield_Sleep_t sleep = shield->EntryPoint;

    // save main memory page address before encrypt
    void* mmp = shield->MainMemPage;

    // encrypt main memory page
    byte key[CRYPTO_KEY_SIZE];
    byte iv [CRYPTO_IV_SIZE];
    RandBuffer(key, CRYPTO_KEY_SIZE);
    RandBuffer(iv,  CRYPTO_IV_SIZE);
    EncryptBuffer(mmp, MAIN_MEM_PAGE_SIZE, key, iv);

    // call shield stub
    sleep(&args);

    // decrypt main memory page
    DecryptBuffer(mmp, MAIN_MEM_PAGE_SIZE, key, iv);

    // erase key data in stack
    mem_init(&args, sizeof(args));
    mem_init(key, sizeof(key));
    mem_init(iv,  sizeof(iv));
    return NO_ERROR;
}

__declspec(noinline)
void SD_Stop(uint32 code)
{
    Shield* shield = getShieldPointer();

    sd_clean(shield);

    // build stop arguments
    Stop_Args args = {
        .Method = METHOD_STOP,

        .VirtualProtect = shield->VirtualProtect,
        .VirtualFree    = shield->VirtualFree,
        .ExitThread     = shield->ExitThread,

        .CriticalAddr = shield->InstAddr,
        .CriticalSize = shield->InstSize,
        .DecoyAddr    = shield->DecoyAddr,
        .DecoySize    = shield->DecoySize,

        .ExitCode = code,
    };

    // save entry point before release main page
    typedef void (*Shield_Stop_t)(Stop_Args* args);
    Shield_Stop_t stop = shield->EntryPoint;

    // copy variables before call EraseBuffer
    VirtualFree_t virtualFree = shield->VirtualFree;
    void* mmp = shield->MainMemPage;

    // release main memory page
    EraseBuffer(mmp, MAIN_MEM_PAGE_SIZE);
    virtualFree(mmp, 0, MEM_RELEASE);

    // call shield stub
    stop(&args);
}

__declspec(noinline)
errno SD_Clean()
{
    Shield* shield = getShieldPointer();

    // free memory for shield
    if (shield->ShieldPage != NULL)
    {
        shield->VirtualFree(shield->ShieldPage, 0, MEM_RELEASE);
    }
    return sd_clean(shield);
}

__declspec(noinline)
static errno sd_clean(Shield* shield)
{
    errno errno = NO_ERROR;

    // free memory for shelter
    if (!shield->VirtualFree(shield->Shelter, 0, MEM_RELEASE) && errno == NO_ERROR)
    {
        errno = ERR_SHIELD_FREE_SHELTER;
    }

    // close timer for sleep
    if (!shield->CloseHandle(shield->Timer) && errno == NO_ERROR)
    {
        errno = ERR_SHIELD_CLOSE_TIMER;
    }
    return errno;
}
