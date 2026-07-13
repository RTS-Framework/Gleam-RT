#ifndef HASH_API_H
#define HASH_API_H

#include "c_types.h"
#include "win_types.h"
#include "win_structs.h"

// Process Module List (PML).
//
// Runtime abstraction of a process module.
//
// The runtime consumes PML as the canonical module representation.
// By default, PML instances are backed by InMemoryOrderModuleList,
// providing real-time synchronization with the Windows loader.
// Alternative providers may construct PML entries from custom module
// sources when required.
//
// PML can be populated from various module providers, including:
//   - InMemoryOrderModuleList (native Windows loader)
//   - Runtime-generated module snapshots
//   - Other module enumeration methods
//   - Custom PE loaders
//
// The Links field represents the active list linkage for the selected
// provider and is not tied to any specific Windows loader list.
//
// Layout-compatible with the leading fields of LDR_DATA_TABLE_ENTRY.
typedef struct {
    LIST_ENTRY Padding0;
    LIST_ENTRY Links;
    LIST_ENTRY Padding1;

    PVOID ImageBase;
    PVOID Padding2;
    ULONG Padding3;

    UNICODE_STRING Padding4;
    UNICODE_STRING BaseName;
} PML;

// FindMod like GetModuleHandle, but provide module name hash and key.
//
// FindAPI will not call GetProcAddress, if this module is not loaded,
// it cannot find the target procedure address.
//
// FindAPI is support forwarded exports.
// FindAPI is NOT support DLL about API Sets.
//
// When the procedure hash is HASH_API_ORDINAL, set the argument
// key to the target function ordinal for try to get it.
//
// FindAPI is NOT support multi forwarded exports with ordinal.

#define HASHAPI_ORDINAL 0xFFFFFFFF

// MH means with module hash. MA means with module address(HMODULE).
typedef void* (*FindMod_MH_t)(uint  module, uint key);
typedef void* (*FindAPI_MA_t)(void* module, uint procedure, uint key);
typedef void* (*FindAPI_MH_t)(uint  module, uint procedure, uint key);

// M*L means operate on a caller-provided PML provider.
typedef void* (*FindMod_MHL_t)(PML* pml, uint  module, uint key);
typedef void* (*FindAPI_MAL_t)(PML* pml, void* module, uint procedure, uint key);
typedef void* (*FindAPI_MHL_t)(PML* pml, uint  module, uint procedure, uint key);

// shortcut for debug, test and toolchain.
typedef void* (*FindMod_A_t)(byte*   module);
typedef void* (*FindMod_W_t)(uint16* module);
typedef void* (*FindAPI_A_t)(byte*   module, byte* procedure);
typedef void* (*FindAPI_W_t)(uint16* module, byte* procedure);

// find module/procedure address with hash and key.
void* FindMod_MH(uint  module, uint key);
void* FindAPI_MA(void* module, uint procedure, uint key);
void* FindAPI_MH(uint  module, uint procedure, uint key);

// find module/procedure address with custom PML.
void* FindMod_MHL(PML* pml, uint  module, uint key);
void* FindAPI_MAL(PML* pml, void* module, uint procedure, uint key);
void* FindAPI_MHL(PML* pml, uint  module, uint procedure, uint key);

// FindMod_A/W is used to find module address(HMODULE) by module name
// with ANSI/UTF-16, it is a wrapper about FindMod_MH and FindMod_MHL.
void* FindMod_A(byte*   module);
void* FindMod_W(uint16* module);

// FindAPI_A/W is used to find Windows API address by module name and
// procedure name with ANSI/UTF-16, it is a wrapper about FindAPI_Mx.
void* FindAPI_A(byte*   module, byte* procedure);
void* FindAPI_W(uint16* module, byte* procedure);

// CalcModHash_A/W is used to calculate module name hash with ANSI/UTF-16.
uint CalcModHash_A(byte*   module, uint key);
uint CalcModHash_W(uint16* module, uint key);

uint32 CalcModHash32_A(byte*   module, uint32 key);
uint32 CalcModHash32_W(uint16* module, uint32 key);
uint64 CalcModHash64_A(byte*   module, uint64 key);
uint64 CalcModHash64_W(uint16* module, uint64 key);

// CalcProcHash is used to calculate procedure name hash with key.
uint   CalcProcHash  (byte* procedure, uint   key);
uint32 CalcProcHash32(byte* procedure, uint32 key);
uint64 CalcProcHash64(byte* procedure, uint64 key);

// get default process module list.
PML* GetDefaultPML();

#endif // HASH_API_H
