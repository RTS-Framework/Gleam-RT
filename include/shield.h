#ifndef SHIELD_H
#define SHIELD_H

#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"

// +------------+---------+-------------+--------+------------+-------+
// | magic mark | xor key | shield size | shield | decoy size | decoy |
// +------------+---------+-------------+--------+------------+-------+
// |    0xFB    | 32 byte |   uint16    |   var  |   uint16   |  var  |
// +------------+---------+-------------+--------+------------+-------+

void Shield_Sleep(DWORD dwMilliseconds);

void Shield_Exit();

typedef struct {
    uintptr BeginAddress;
    uintptr EndAddress;
    byte    CryptoKey[32];
    HANDLE  hTimer;

    WaitForSingleObject_t WaitForSingleObject;
} Shield_Ctx;

bool DefenseRT(Shield_Ctx* ctx);

// reserve stub for store shield and decoy
#pragma warning(push)
#pragma warning(disable : 4276)
extern void Shield_Stub(void* args);
#pragma warning(pop)

#endif // SHIELD_H
