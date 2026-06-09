#ifndef WIN_API_H
#define WIN_API_H

#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"

typedef struct {
    struct LIST_ENTRY* Flink;
    struct LIST_ENTRY* Blink;
} LIST_ENTRY;

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct {
    ULONG  Length;
    BOOL   Initialized;
    HANDLE SsHandle;

    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA;

typedef struct {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;

    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;

    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY;

typedef struct {
    bool InheritedAddressSpace;
    bool ReadImageFileExecOptions;
    bool BeingDebugged;
    bool SpareBool;

    HANDLE Mutant;
    PVOID  ImageBaseAddress;

    PEB_LDR_DATA* Ldr;
} PEB;

typedef struct {
    PVOID NtTib;
    PVOID EnvironmentPointer;
    PVOID ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTib;
    PVOID FiberData;
    PVOID ArbitraryUserPointer;
    struct TEB* Self;
    PVOID EnvironmentBlock;
} TEB;

DWORD   GetModuleFileName(void* list, HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
HMODULE GetModuleHandle(void* list, LPWSTR lpFilename);

#endif // WIN_API_H
