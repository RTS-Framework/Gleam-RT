#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "hash_api.h"
#include "win_api.h"

BOOL IsValidModuleHandle(PML* pml, HMODULE hModule)
{
    if (hModule == NULL)
    {
        return false;
    }
    LIST_ENTRY* head = &pml->Links;
    for (LIST_ENTRY* link = head->Flink; link != head; link = link->Flink)
    {
        PML* entry = (PML*)((uintptr)(link)-offsetof(PML, Links));
        if (entry->ImageBase == hModule)
        {
            return true;
        }
    }
    return false;
}

DWORD GetModuleBaseNameW(PML* pml, HMODULE hModule, PWSTR lpBasename, DWORD nSize)
{
    LIST_ENTRY* head = &pml->Links;
    for (LIST_ENTRY* link = head->Flink; link != head; link = link->Flink)
    {
        PML* entry = (PML*)((uintptr)(link)-offsetof(PML, Links));
        if (entry->ImageBase != hModule)
        {
            continue;
        }
        PWSTR  nameBuf = entry->BaseName.Buffer;
        USHORT nameLen = entry->BaseName.Length;
        if (nameLen > nSize*2)
        {
            nameLen = (USHORT)(nSize*2);
        }
        mem_copy(lpBasename, nameBuf, nameLen);
        return nameLen;
    }
    return 0;
}

HMODULE GetModuleHandleW(PML* pml, PWSTR lpBasename)
{
    LIST_ENTRY* head = &pml->Links;
    for (LIST_ENTRY* link = head->Flink; link != head; link = link->Flink)
    {
        PML* entry = (PML*)((uintptr)(link)-offsetof(PML, Links));
        PWSTR  nameBuf = entry->BaseName.Buffer;
        USHORT nameLen = entry->BaseName.Length/2;
        if (strnicmp_w(lpBasename, nameBuf, nameLen) == 0)
        {
            return entry->ImageBase;
        }
    }
    return NULL;
}
