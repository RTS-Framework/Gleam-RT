#ifndef PTR_TABLE_H
#define PTR_TABLE_H

#include "c_types.h"
#include "rel_addr.h"

// +------------+----------+----------+
// | magic mark | reserved | pointers |
// +------------+----------+----------+
// |    0xFA    |  7 byte  | 248 byte |
// +------------+----------+----------+

#define POINTER_STUB_MAGIC  0xFA
#define POINTER_STUB_SIZE   256

#define POINTER_ADDR_PREFIX (uintptr)(GetFuncAddr(&Pointer_Stub))

#define POINTER_OFFSET_RUNTIME           (POINTER_ADDR_PREFIX + 0x08)
#define POINTER_OFFSET_SPOOF_CALL        (POINTER_ADDR_PREFIX + 0x10)
#define POINTER_OFFSET_INDIRECT_SYSCALL  (POINTER_ADDR_PREFIX + 0x18)
#define POINTER_OFFSET_DETECTOR          (POINTER_ADDR_PREFIX + 0x20)
#define POINTER_OFFSET_LIBRARY_TRACKER   (POINTER_ADDR_PREFIX + 0x28)
#define POINTER_OFFSET_MEMORY_TRACKER    (POINTER_ADDR_PREFIX + 0x30)
#define POINTER_OFFSET_THREAD_TRACKER    (POINTER_ADDR_PREFIX + 0x38)
#define POINTER_OFFSET_RESOURCE_TRACKER  (POINTER_ADDR_PREFIX + 0x40)
#define POINTER_OFFSET_ARGUMENT_STORE    (POINTER_ADDR_PREFIX + 0x48)
#define POINTER_OFFSET_IN_MEMORY_STORAGE (POINTER_ADDR_PREFIX + 0x50)
#define POINTER_OFFSET_WIN_BASE          (POINTER_ADDR_PREFIX + 0x58)
#define POINTER_OFFSET_WIN_FILE          (POINTER_ADDR_PREFIX + 0x60)
#define POINTER_OFFSET_WIN_HTTP          (POINTER_ADDR_PREFIX + 0x68)
#define POINTER_OFFSET_WIN_CRYPTO        (POINTER_ADDR_PREFIX + 0x70)
#define POINTER_OFFSET_WATCHDOG          (POINTER_ADDR_PREFIX + 0x78)
#define POINTER_OFFSET_SYSMON            (POINTER_ADDR_PREFIX + 0x80)
#define POINTER_OFFSET_SHIELD            (POINTER_ADDR_PREFIX + 0x88)

// reserve stub for store module pointer
#pragma warning(push)
#pragma warning(disable: 4276)
extern void Pointer_Stub();
#pragma warning(pop)

#endif // PTR_TABLE_H
