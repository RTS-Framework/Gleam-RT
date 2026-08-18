#ifndef MOD_ARGUMENT_H
#define MOD_ARGUMENT_H

#include "c_types.h"
#include "win_types.h"
#include "errno.h"
#include "context.h"

// +------+---------+----------+-----------+----------+--------+----------+----------+
// | init |   key   | num args | args size | checksum | arg id | arg size | arg data |
// +------+---------+----------+-----------+----------+--------+----------+----------+
// | bool | 32 byte |  uint16  |  uint32   |  uint32  | uint32 |  uint32  |   var    |
// +------+---------+----------+-----------+----------+--------+----------+----------+

#define ARG_MAX_NUM_ARGUMENTS 1024
#define ARG_ALGO_SWITCH_SIZE  512

#define ARG_CRYPTO_KEY_SIZE (32)
#define ARG_HEADER_SIZE     (1 + 32 + 2 + 4 + 4)

#define ARG_OFFSET_CRYPTO_KEY (1)
#define ARG_OFFSET_NUM_ARGS   (1 + 32)
#define ARG_OFFSET_ARGS_SIZE  (1 + 32 + 2)
#define ARG_OFFSET_CHECKSUM   (1 + 32 + 2 + 4)
#define ARG_OFFSET_FIRST_ARG  (1 + 32 + 2 + 4 + 4)

typedef struct {
    int32 NumItems;
    int32 NumErased;
    int64 TotalSize;
} AS_Status;

typedef BOOL (*ArgGetValue_t)(uint32 id, void* value, uint32* size);
typedef BOOL (*ArgGetPointer_t)(uint32 id, void** pointer, uint32* size);
typedef BOOL (*ArgErase_t)(uint32 id);
typedef void (*ArgEraseAll_t)();
typedef BOOL (*ArgGetStatus_t)(AS_Status* status);

typedef bool  (*ArgLock_t)();
typedef bool  (*ArgUnlock_t)();
typedef errno (*ArgEncrypt_t)();
typedef errno (*ArgDecrypt_t)();
typedef errno (*ArgClean_t)();

typedef struct {
    // for user
    ArgGetValue_t   GetValue;
    ArgGetPointer_t GetPointer;
    ArgErase_t      Erase;
    ArgEraseAll_t   EraseAll;
    ArgGetStatus_t  GetStatus;

    // for runtime internal usage
    ArgLock_t    Lock;
    ArgUnlock_t  Unlock;
    ArgEncrypt_t Encrypt;
    ArgDecrypt_t Decrypt;
    ArgClean_t   Clean;

    // data for sysmon
    HANDLE hMutex;
} ArgumentStore_M;

ArgumentStore_M* InitArgumentStore(Context* context);

// reserve stub for store arguments
#pragma warning(push)
#pragma warning(disable: 4276)
extern void Argument_Stub();
#pragma warning(pop)

#endif // MOD_ARGUMENT_H
