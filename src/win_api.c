#include "c_types.h"
#include "win_types.h"
#include "win_structs.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "hash_api.h"
#include "pe_image.h"
#include "win_api.h"

static LPSTR getProcedureName(HMODULE hModule, void* procedure);

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

LPSTR GetProcedureName(PML* pml, HMODULE hModule, void* procedure)
{
    if (procedure == NULL)
    {
        return NULL;
    }
    // try to get procedure name from self module first
    if (hModule != NULL)
    {
        LPSTR name = getProcedureName(hModule, procedure);
        if (name != NULL)
        {
            return name;
        }
    }
    // if not exist, search procedure name from pml.
    // like forwarded procedure in EAT.
    LIST_ENTRY* head = &pml->Links;
    for (LIST_ENTRY* link = head->Flink; link != head; link = link->Flink)
    {
        PML* entry = (PML*)((uintptr)(link)-offsetof(PML, Links));
        LPSTR name = getProcedureName(entry->ImageBase, procedure);
        if (name != NULL)
        {
            return name;
        }
    }
    return NULL;
}

static LPSTR getProcedureName(HMODULE hModule, void* procedure)
{
    uintptr proc = (uintptr)procedure;
    // check image base address is expected
    uintptr base = (uintptr)(hModule);
    // parse module information
    PE_Image image;
    mem_init(&image, sizeof(image));
    ParsePEImage(hModule, &image);
    // calculate the text section range
    uintptr begin = base + image.Text.VirtualAddress;
    uintptr end = begin + image.Text.VirtualSize;
    if (proc < begin || proc >= end)
    {
        // erase data in the large stack
        mem_init(&image, sizeof(image));
        return NULL;
    }
    // get RVA of export address tables(EAT)
    Image_DataDirectory* DD = &image.OptionalHeader.DataDirectory[0];
    Image_DataDirectory  EAT = DD[IMAGE_DIRECTORY_ENTRY_EXPORT];
    // get export directory structure
    Image_ExportDirectory* dir = (Image_ExportDirectory*)(base + EAT.VirtualAddress);
    // process EAT arrays
    uint32* funcTable = (uint32*)(base + dir->AddressOfFunctions);
    uint32* nameTable = (uint32*)(base + dir->AddressOfNames);
    uint16* ordiTable = (uint16*)(base + dir->AddressOfNameOrdinals);
    uint32  numNames  = dir->NumberOfNames;
    // erase data in the large stack
    mem_init(&image, sizeof(image));
    // compare the exported function address
    for (uint32 i = 0; i < numNames; i++)
    {
        // name[i] -> ordinal[i] -> funcRVA[ordinal]
        uint32 funcRVA = funcTable[ordiTable[i]];
        if (base + funcRVA == proc)
        {
            // get procedure name address
            byte* procName = (byte*)(base + nameTable[i]);
            return procName;
        }
    }
    return NULL;
}
