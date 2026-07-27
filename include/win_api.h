#ifndef WIN_API_H
#define WIN_API_H

#include "c_types.h"
#include "win_types.h"
#include "win_structs.h"
#include "dll_kernel32.h"
#include "hash_api.h"

// some function names have been slightly modified
// to avoid conflicts with kernel32.lib.

// IsValidModuleHandle is used to check module handle is valid.
BOOL IsValidModuleHandle(PML* pml, HMODULE hModule);

// GetModuleBaseName is used to get module base name by handle.
DWORD GetModuleBaseName(PML* pml, HMODULE hModule, LPWSTR lpBasename, DWORD nSize);

// GetModuleHandle is used to get module handle by base name.
HMODULE GetModuleHandle(PML* pml, LPWSTR lpBasename);

// GetProcedureName is used to get procedure name by address.
LPSTR GetProcedureName(PML* pml, HMODULE hModule, void* procedure);

#endif // WIN_API_H
