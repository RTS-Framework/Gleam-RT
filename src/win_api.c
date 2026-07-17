#include "c_types.h"
#include "win_types.h"
#include "win_structs.h"
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

DWORD GetModuleBaseName(PML* pml, HMODULE hModule, LPWSTR lpBasename, DWORD nSize)
{
    if (hModule == NULL || lpBasename == NULL || nSize == 0)
    {
        return 0;
    }
    LIST_ENTRY* head = &pml->Links;
    for (LIST_ENTRY* link = head->Flink; link != head; link = link->Flink)
    {
        PML* entry = (PML*)((uintptr)(link)-offsetof(PML, Links));
        if (entry->ImageBase != hModule)
        {
            continue;
        }
        LPWSTR nameBuf = entry->BaseName.Buffer;
        USHORT nameLen = entry->BaseName.Length/2;
        if (nameLen >= nSize)
        {
            nameLen = (USHORT)(nSize-1);
        }
        strncpy_w(lpBasename, nameBuf, nameLen);
        lpBasename[nameLen] = 0x0000;
        return nameLen;
    }
    return 0;
}

HMODULE GetModuleHandle(PML* pml, LPWSTR lpBasename)
{
    if (lpBasename == NULL)
    {
        return NULL;
    }
    uint len = strlen_w(lpBasename);
    LIST_ENTRY* head = &pml->Links;
    for (LIST_ENTRY* link = head->Flink; link != head; link = link->Flink)
    {
        PML* entry = (PML*)((uintptr)(link)-offsetof(PML, Links));
        LPWSTR nameBuf = entry->BaseName.Buffer;
        USHORT nameLen = entry->BaseName.Length/2;
        if (nameLen != len)
        {
            continue;
        }
        if (strnicmp_w(lpBasename, nameBuf, nameLen) == 0)
        {
            return entry->ImageBase;
        }
    }
    return NULL;
}
