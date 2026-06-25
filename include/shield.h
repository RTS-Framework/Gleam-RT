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

#define SHIELD_STUB_MAGIC 0xFB
#define SHIELD_STUB_SIZE  (8 * 1024)
#define SHIELD_KEY_SIZE   32

#define SHIELD_SRC_PRE_INJECTED 1
#define SHIELD_SRC_SHIELD_STUB  2
#define SHIELD_SRC_EXTERNAL     3

#define SHIELD_MAIN_MODULE 0x0001

typedef struct {
    void* EntryPoint;
    void* BaseAddress;
    int64 Source;
} SD_Status;

typedef BOOL (*SDGetStatus_t)(SD_Status* status);

typedef errno (*SDSleep_t)(uint32 milliseconds);
typedef void  (*SDStop_t)();
typedef errno (*SDClean_t)();

typedef struct {
    // for user
    SDGetStatus_t GetStatus;

    // for runtime internal usage
    SDSleep_t Sleep;
    SDStop_t  Stop;
    SDClean_t Clean;
} Shield_M;

Shield_M* InitShield(Context* context);

// reserved stub for store shield and decoy
#pragma warning(push)
#pragma warning(disable : 4276)
extern void Shield_Stub();
#pragma warning(pop)

#endif // SHIELD_H
