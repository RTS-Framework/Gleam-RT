#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "hash_api.h"
#include "random.h"
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

    VirtualProtect_t      VirtualProtect;
    VirtualFree_t         VirtualFree;
    ExitThread_t          ExitThread;
    WaitForSingleObject_t WaitForSingleObject;

    // global mutex
    HANDLE hMutex;

    SD_Status status;
} Shield;

// methods for user
BOOL SD_GetStatus(SD_Status* status);

// methods for runtime
bool  SD_Lock();
bool  SD_Unlock();
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
    method->Lock   = GetFuncAddr(&SD_Lock);
    method->Unlock = GetFuncAddr(&SD_Unlock);
    method->Sleep  = GetFuncAddr(&SD_Sleep);
    method->Stop   = GetFuncAddr(&SD_Stop);
    method->Clean  = GetFuncAddr(&SD_Clean);
    return method;
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
