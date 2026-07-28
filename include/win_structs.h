#ifndef WIN_STRUCTS_H
#define WIN_STRUCTS_H

#include "c_types.h"
#include "win_types.h"

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
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

    UCHAR ImageUsedLargePages          :1;
    UCHAR IsProtectedProcess           :1;
    UCHAR IsImageDynamicallyRelocated  :1;
    UCHAR SkipPatchingUser32Forwarders :1;
    UCHAR IsPackagedProcess            :1;
    UCHAR IsAppContainer               :1;
    UCHAR IsProtectedProcessLight      :1;
    UCHAR IsLongPathAwareProcess       :1;

    HANDLE Mutant;
    PVOID  ImageBaseAddress;

    PEB_LDR_DATA* LDR;

    PVOID  ProcessParameters;
    PVOID  SubSystemData;
    HANDLE ProcessHeap;
    PVOID  FastPEBLock;
    PVOID  AtlThunkSListPtr;
    PVOID  IFEOKey;

    ULONG ProcessInJob               :1;
    ULONG ProcessInitializing        :1;
    ULONG ProcessUsingVEH            :1;
    ULONG ProcessUsingVCH            :1;
    ULONG ProcessUsingFTH            :1;
    ULONG ProcessPreviouslyThrottled :1;
    ULONG ProcessCurrentlyThrottled  :1;
    ULONG ProcessImagesHotPatched    :1;
    ULONG ReservedBits0              :24;

    PVOID KernelCallbackTable;
    ULONG Reserved;
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
} PEB;

typedef struct _NT_TIB {
    PVOID ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTIB;
    PVOID FiberData;
    PVOID ArbitraryUserPointer;
    struct _NT_TIB* Self;
} NT_TIB;

typedef struct {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct {
    NT_TIB    TIB;
    PVOID     EnvironmentPointer;
    CLIENT_ID ClientID;
    PVOID     ActiveRpcHandle;
    PVOID     ThreadLocalStoragePointer;
    PEB*      ProcessEnvironmentBlock;
    ULONG     LastErrorValue;
    ULONG     CountOfOwnedCriticalSections;
    PVOID     CsrClientThread;
    PVOID     Win32ThreadInfo;
} TEB;

#endif // WIN_STRUCTS_H
