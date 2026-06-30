#ifndef WIN_STRUCT_H
#define WIN_STRUCT_H

#include "c_types.h"
#include "win_types.h"

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
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN BitField;

    HANDLE Mutant;
    PVOID  ImageBaseAddress;
    PEB_LDR_DATA* Ldr;
    PVOID  ProcessParameters;
    PVOID  SubSystemData;
    PVOID  ProcessHeap;
    PVOID  FastPebLock;
    PVOID  AtlThunkSListPtr;
    PVOID  IFEOKey;
    ULONG  CrossProcessFlags;
    ULONG  NumberOfProcessors;
    ULONG  NtGlobalFlag;
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
    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    PVOID ProcessEnvironmentBlock;
} TEB;

#endif // WIN_STRUCT_H

