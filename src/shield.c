#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "hash_api.h"
#include "random.h"
#include "crypto.h"
#include "errno.h"
#include "context.h"
#include "layout.h"
#include "shield.h"
#include "debug.h"

#define METHOD_SLEEP 1
#define METHOD_STOP  2

typedef struct {
    uintptr Method;

    VirtualProtect_t      VirtualProtect;
    WaitForSingleObject_t WaitForSingleObject;
    uintptr               Reserved;

    uintptr CriticalAddr;
    uint    CriticalSize;
    uintptr DecoyAddr;
    uint    DecoySize;

    uintptr Shelter;
    HANDLE  Timer;
} Sleep_Args;

typedef struct {
    uintptr Method;

    VirtualProtect_t VirtualProtect;
    VirtualFree_t    VirtualFree;
    ExitThread_t     ExitThread;

    uintptr CriticalAddr;
    uint    CriticalSize;
    uintptr DecoyAddr;
    uint    DecoySize;
} Stop_Args;

typedef struct {
    // store options
    bool NotEraseInstruction;
    bool NotAdjustProtect;

    VirtualAlloc_t         VirtualAlloc;
    VirtualFree_t          VirtualFree;
    VirtualProtect_t       VirtualProtect;
    ExitThread_t           ExitThread;
    SetWaitableTimer_t     SetWaitableTimer;
    WaitForSingleObject_t  WaitForSingleObject;
    CloseHandle_t          CloseHandle;

    // runtime data
    uintptr MainMemPage;
    uintptr InstAddr;
    uint    InstSize;

    // about decoy and shelter
    uintptr DecoyAddr;
    uint    DecoySize;
    uintptr Shelter;

    // shield entry point
    void* EntryPoint;

    // allocated shield address
    void* MemPage;

    // for sleep
    HANDLE Timer;

    SD_Status status;
} Shield;

// methods for user
BOOL SD_GetStatus(SD_Status* status);

// methods for runtime
errno SD_Sleep(uint32 milliseconds);
void  SD_Stop();
errno SD_Clean();

// hard encoded address in getShieldPointer for replacement
#ifdef _WIN64
    #define SHIELD_POINTER 0x7FABCDEF111111FF
#elif _WIN32
    #define SHIELD_POINTER 0x7FABCDFF
#endif
static Shield* getShieldPointer();

static bool initShieldAPI(Shield* shield, Context* context);
static bool updateShieldPointer(Shield* shield);
static bool recoverShieldPointer(Shield* shield);
static bool initShieldEnvironment(Shield* shield, Context* context);
static void eraseShieldMethods(Context* context);
static void cleanShield(Shield* shield);

Shield_M* InitShield(Context* context)
{
    // set structure address
    uintptr addr = context->MainMemPage;
    uintptr shieldAddr = addr + LAYOUT_SD_STRUCT + RandUintN(addr, 128);
    uintptr methodAddr = addr + LAYOUT_SD_METHOD + RandUintN(addr, 128);
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
        if (!updateShieldPointer(shield))
        {
            errno = ERR_SHIELD_UPDATE_PTR;
            break;
        }
        if (!initShieldEnvironment(shield, context))
        {
            errno = ERR_SHIELD_INIT_ENV;
            break;
        }
        break;
    }
    eraseShieldMethods(context);
    if (errno != NO_ERROR)
    {
        SetLastErrno(errno);
        return NULL;
    }
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
    // copy from context
    shield->VirtualAlloc     = context->VirtualAlloc;
    shield->SetWaitableTimer = context->SetWaitableTimer;
    shield->CloseHandle      = context->CloseHandle;

    // if the shield stub is NOT pre-injected, use copy from context
    if (context->ShieldModuleHash == 0)
    {
        shield->VirtualFree         = context->VirtualFree;
        shield->VirtualProtect      = context->VirtualProtect;
        shield->ExitThread          = context->ExitThread;
        shield->WaitForSingleObject = context->WaitForSingleObject;
        return true;
    }

    // get original API address
    typedef struct { 
        uint mHash; uint pHash; uint hKey; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0xB81CFE7E68817EBC, 0x9ED80CDB7C8DC7CB, 0x93DEFC8B369AEB09 }, // VirtualFree
        { 0x09DCD4916EAF02FB, 0x07847A7F31B555AA, 0xE8CD656DB309997E }, // VirtualProtect
        { 0xB7A6984C86379802, 0x47310D64BDB74A5A, 0xB770E3DCC3F639EF }, // ExitThread
        { 0xBF4577A186DA850B, 0x7084089B2EECD03E, 0x859DED82D1FEBB27 }, // WaitForSingleObject
    };
#elif _WIN32
    {
        { 0xC80B8735, 0x6E1ADA58, 0xF607BBCE }, // VirtualFree
        { 0x10AA34C4, 0xC5560D17, 0xB641E477 }, // VirtualProtect
        { 0x88FF610F, 0xCE1AB90A, 0x1CA2C5D8 }, // ExitThread
        { 0xEE6856BE, 0xB1FF31C3, 0xA11C1DDA }, // WaitForSingleObject
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        winapi item = list[i];
        void*  proc = FindAPI(item.mHash, item.pHash, item.hKey);
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
    return true;
}

// CANNOT merge updateShieldPointer and recoverShieldPointer
// to one function with two arguments, otherwise the compiler
// will generate the incorrect instructions.

__declspec(noinline)
static bool updateShieldPointer(Shield* shield)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getShieldPointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != SHIELD_POINTER)
        {
            target++;
            continue;
        }
        *pointer = (uintptr)shield;
        success = true;
        break;
    }
    return success;
}

__declspec(noinline)
static bool recoverShieldPointer(Shield* shield)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getShieldPointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != (uintptr)shield)
        {
            target++;
            continue;
        }
        *pointer = SHIELD_POINTER;
        success = true;
        break;
    }
    return success;
}

static bool initShieldEnvironment(Shield* shield, Context* context)
{
    uintptr stub = (uintptr)(GetFuncAddr(&Shield_Stub));
    // check stub is valid
    if (*(byte*)(stub) != SHIELD_STUB_MAGIC)
    {
        return false;
    }
    // prepare xor key
    byte*  key = (byte*)(stub + 1);
    uint16 off = 1 + SHIELD_KEY_SIZE;
    // decrypt shield
    uint16 size = *(uint16*)(stub + off);
    off += sizeof(uint16);
    byte* shieldInst = (byte*)(stub + off);
    XORBuf(shieldInst, size, key, SHIELD_KEY_SIZE);
    off += size;
    // decrypt decoy
    size = *(uint16*)(stub + off);
    off += sizeof(uint16);
    byte* decoyInst = (byte*)(stub + off);
    XORBuf(decoyInst, size, key, SHIELD_KEY_SIZE);

    if (context->ShieldModuleHash != 0)
    {

    }

    // prepare VirtualProtect address
    if (shield->NotAdjustProtect)
    {
        shield->VirtualProtect = NULL;
    }
    // align instance size to 4 or 8
    uint instSize = context->InstSize;
    instSize = ((instSize + sizeof(uint) - 1) / instSize) * instSize;
    shield->InstSize = instSize;
    // copy runtime data
    shield->MainMemPage = context->MainMemPage;
}

static void eraseShieldMethods(Context* context)
{
    if (context->NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&initShieldAPI));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseShieldMethods));
    uintptr size  = end - begin;
    RandBuffer((byte*)begin, (int64)size);
}

static void cleanShield(Shield* shield)
{

}

// updateShieldPointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateShieldPointer will fail.
#pragma optimize("", off)
static Shield* getShieldPointer()
{
    uintptr pointer = SHIELD_POINTER;
    return (Shield*)(pointer);
}
#pragma optimize("", on)

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

    // encrypt main memory page
    void* mmp = (void*)(shield->MainMemPage);
    byte key[CRYPTO_KEY_SIZE];
    byte iv [CRYPTO_IV_SIZE];
    RandBuffer(key, CRYPTO_KEY_SIZE);
    RandBuffer(iv,  CRYPTO_IV_SIZE);
    EncryptBuf(mmp, MAIN_MEM_PAGE_SIZE, key, iv);

    // call shield stub
    typedef void (*Shield_Sleep_t)(Sleep_Args* args);
    Shield_Sleep_t sleep = shield->EntryPoint;
    sleep(&args);

    // decrypt main memory page
    DecryptBuf(mmp, MAIN_MEM_PAGE_SIZE, key, iv);
    return NO_ERROR;
}

__declspec(noinline)
void SD_Stop()
{
    Shield* shield = getShieldPointer();

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
    };

    // call shield stub
    typedef void (*Shield_Stop_t)(Stop_Args* args);
    Shield_Stop_t stop = shield->EntryPoint;
    stop(&args);
}

__declspec(noinline)
errno SD_Clean()
{

}
