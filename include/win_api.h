#ifndef WIN_API_H
#define WIN_API_H

#include "c_types.h"
#include "win_types.h"
#include "win_structs.h"
#include "dll_kernel32.h"
#include "hash_api.h"

// IsValidModuleHandle is used to check module handle is valid.
BOOL IsValidModuleHandle(PML* pml, HMODULE hModule);

// GetModuleBaseNameW is used to get module base name by handle.
DWORD GetModuleBaseNameW(PML* pml, HMODULE hModule, LPWSTR lpBasename, DWORD nSize);

// GetModuleHandleW is used to get module handle by base name.
HMODULE GetModuleHandleW(PML* pml, LPWSTR lpBasename);

// IsDebuggerPresent is used to check current process is being debugged.
BOOL IsDebuggerPresent(PEB* peb);

#endif // WIN_API_H
