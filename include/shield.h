#ifndef SHIELD_H
#define SHIELD_H

#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "errno.h"
#include "context.h"

// +------------+---------+-------------+--------+------------+-------+
// | magic mark | xor key | shield size | shield | decoy size | decoy |
// +------------+---------+-------------+--------+------------+-------+
// |    0xFB    | 32 byte |   uint16    |   var  |   uint16   |  var  |
// +------------+---------+-------------+--------+------------+-------+

typedef struct {
    void* EntryPoint;
    void* BaseAddress;
    BOOL  IsPreInjected;
    BOOL  IsAllocated;
} SD_Status;

typedef BOOL (*SDGetStatus_t)(SD_Status* status);

typedef bool  (*SDLock_t)();
typedef bool  (*SDUnlock_t)();
typedef void  (*SDSleep_t)(DWORD dwMilliseconds);
typedef void  (*SDStop_t)();
typedef errno (*SDClean_t)();

typedef struct {
    // for user
    SDGetStatus_t GetStatus;

    // for runtime internal usage
    SDLock_t   Lock;
    SDUnlock_t Unlock;
    SDSleep_t  Sleep;
    SDStop_t   Stop;
    SDClean_t  Clean;

    // data for runtime
    HANDLE hMutex;
} Shield_M;

Shield_M* InitShield(Context* context);

typedef struct {
    uintptr BeginAddress;
    uintptr EndAddress;
    byte    CryptoKey[32];
    HANDLE  hTimer;

    WaitForSingleObject_t WaitForSingleObject;
} Shield_Ctx;

bool DefenseRT(Shield_Ctx* ctx);

// reserved stub for store shield and decoy
#pragma warning(push)
#pragma warning(disable : 4276)
extern void Shield_Stub();
#pragma warning(pop)

#endif // SHIELD_H
