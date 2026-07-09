#ifndef WIN_API_H
#define WIN_API_H

#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "hash_api.h"

// IsValidModuleHandle is used to check module handle is valid.
BOOL IsValidModuleHandle(PML* pml, HMODULE hModule);

// GetModuleBaseNameW is used to get module base name by handle.
DWORD GetModuleBaseNameW(PML* pml, HMODULE hModule, PWSTR lpBasename, DWORD nSize);

// GetModuleHandleW is used to get module handle by base name.
HMODULE GetModuleHandleW(PML* pml, PWSTR lpBasename);

#endif // WIN_API_H
