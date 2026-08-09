#include "c_types.h"
#include "win_types.h"
#include "win_structs.h"
#include "lib_memory.h"
#include "pe_image.h"
#include "hash_api.h"

#ifdef _WIN64
    #define KEY_SIZE 8
    #define ROR_BITS 8
#elif _WIN32
    #define KEY_SIZE 4
    #define ROR_BITS 4
#endif

#define ROR_SEED (ROR_BITS + 1)
#define ROR_KEY  (ROR_BITS + 2)
#define ROR_MOD  (ROR_BITS + 3)
#define ROR_PROC (ROR_BITS + 4)

static uint calcSeedHash(uint key);
static uint calcKeyHash(uint seed, uint key);
static uint ror(uint value, uint bits);

__declspec(noinline)
void* FindMod_MH(uint module, uint key)
{
    PML* pml = GetDefaultPML();
    return FindMod_MHL(pml, module, key);
}

__declspec(noinline)
void* FindAPI_MA(void* module, uint procedure, uint key)
{
    PML* pml = GetDefaultPML();
    return FindAPI_MAL(pml, module, procedure, key);
}

__declspec(noinline)
void* FindAPI_MH(uint module, uint procedure, uint key)
{
    PML* pml = GetDefaultPML();
    return FindAPI_MHL(pml, module, procedure, key);
}

__declspec(noinline)
void* FindMod_MHL(PML* pml, uint module, uint key)
{
    if (pml == NULL)
    {
        return NULL;
    }
    // prepare hash for calculate
    uint seedHash = calcSeedHash(key);
    uint keyHash  = calcKeyHash(seedHash, key);
    // enumerate the list of modules
    LIST_ENTRY* head = &pml->Links;
    for (LIST_ENTRY* link = head->Flink; link != head; link = link->Flink)
    {
        PML* entry = (PML*)((uintptr)(link) - offsetof(PML, Links));
        // check the module information for prevent
        // the malicious entry in the module list
        PVOID  imgBase = entry->ImageBase;
        PWSTR  nameBuf = entry->BaseName.Buffer;
        USHORT nameLen = entry->BaseName.Length;
        if (imgBase == NULL || nameBuf == NULL || nameLen == 0)
        {
            continue;
        }
        // calculate and compare module name hash
        uint modHash = seedHash;
        for (uint16 i = 0; i < nameLen; i++)
        {
            byte b = *((byte*)nameBuf+i);
            if (b >= 'a')
            {
                b -= 0x20;
            }
            modHash = ror(modHash, ROR_MOD);
            modHash += b;
        }
        modHash += seedHash + keyHash;
        if (modHash != module)
        {
            continue;
        }
        return imgBase;
    }
    return NULL;
}

__declspec(noinline)
void* FindAPI_MAL(PML* pml, void* module, uint procedure, uint key)
{
    if (module == NULL)
    {
        return NULL;
    }
    // prepare hash for calculate
    uint seedHash = calcSeedHash(key);
    uint keyHash  = calcKeyHash(seedHash, key);
    // parse pe image structure
    uintptr dllBase  = (uintptr)(module);
    uintptr ntOffset = (uintptr)(*(uint32*)(dllBase + DOS_HEADER_SIZE - 4));
    Image_NTHeaders* ntHeaders = (Image_NTHeaders*)(dllBase + ntOffset);
#ifdef _WIN64
    // check this module actually a x64 PE image
    if (ntHeaders->OptionalHeader.Magic != 0x020B)
    {
        return NULL;
    }
#endif
    // get RVA of export address tables(EAT)
    Image_DataDirectory* DD = &ntHeaders->OptionalHeader.DataDirectory[0];
    Image_DataDirectory EAT = DD[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (EAT.VirtualAddress == 0 || EAT.Size == 0)
    {
        return NULL;
    }
    // get export directory structure
    Image_ExportDirectory* dir = (Image_ExportDirectory*)(dllBase + EAT.VirtualAddress);
    // process EAT arrays
    uint32* funcTable = (uint32*)(dllBase + dir->AddressOfFunctions);
    uint32* nameTable = (uint32*)(dllBase + dir->AddressOfNames);
    uint16* ordiTable = (uint16*)(dllBase + dir->AddressOfNameOrdinals);
    // try to get function RVA
    uint32 funcRVA = 0;
    if (procedure == HASHAPI_ORDINAL)
    {
        key -= dir->Base;
        if (key < dir->NumberOfFunctions)
        {
            funcRVA = funcTable[key];
        }
    } else {
        for (uint32 i = 0; i < dir->NumberOfNames; i++)
        {
            // lookup procedure name by index
            byte* procName = (byte*)(dllBase + nameTable[i]);
            uint  procHash = seedHash;
            for (;;)
            {
                byte b = *procName;
                if (b == 0x00)
                {
                    break;
                }
                procHash = ror(procHash, ROR_PROC);
                procHash += b;
                procName++;
            }
            // calculate the finally hash and compare it
            procHash += seedHash + keyHash;
            if (procHash != procedure)
            {
                continue;
            }
            // name[i] -> ordinal[i] -> funcRVA[ordinal]
            funcRVA = funcTable[ordiTable[i]];
            break;
        }
    }
    if (funcRVA == 0)
    {
        return NULL;
    }
    // check it is forwarded export function
    if (funcRVA < EAT.VirtualAddress || funcRVA >= EAT.VirtualAddress + EAT.Size)
    {
        return (void*)(dllBase + funcRVA);
    }
    // get the export name
    byte* exportName = (byte*)(dllBase + funcRVA);
    // search the last "." in function name
    byte* src = exportName;
    uint  dot = 0;
    for (uint j = 0;; j++)
    {
        byte b = *src;
        if (b == '.')
        {
            dot = j;
        }
        if (b == 0x00)
        {
            break;
        }
        src++;
    }
    // use "mem_init" for prevent incorrect compiler
    // optimize and generate incorrect instruction
    byte dllName[512];
    mem_init(dllName, sizeof(dllName));
    // prevent array bound when call mem_copy
    if (dot > 500)
    {
        dot = 500;
    }
    mem_copy(dllName, exportName, dot + 1);
    // build DLL name
    dllName[dot + 1] = 'd';
    dllName[dot + 2] = 'l';
    dllName[dot + 3] = 'l';
    dllName[dot + 4] = 0x00;
    // build procedure name
    byte* procName = (byte*)((uintptr)exportName + dot + 1);
    // build module and procedure hash
    uint mHash = CalcModHash_A(dllName, key);
    uint pHash = CalcProcHash(procName, key);
    // erase data in the large stack
    mem_init(dllName, sizeof(dllName));
    return FindAPI_MHL(pml, mHash, pHash, key);
}

__declspec(noinline)
void* FindAPI_MHL(PML* pml, uint module, uint procedure, uint key)
{
    void* mod = FindMod_MHL(pml, module, key);
    if (mod == NULL)
    {
        return mod;
    }
    return FindAPI_MAL(pml, mod, procedure, key);
}

__declspec(noinline)
void* FindMod_A(byte* module)
{
    uint key = 0xFFFFFFFF;
    uint mod = CalcModHash_A(module, key);
    return FindMod_MH(mod, key);
}

__declspec(noinline)
void* FindMod_W(uint16* module)
{
    uint key = 0xFFFFFFFF;
    uint mod = CalcModHash_W(module, key);
    return FindMod_MH(mod, key);
}

__declspec(noinline)
void* FindAPI_A(byte* module, byte* procedure)
{
    uint key  = 0xFFFFFFFF;
    uint mod  = CalcModHash_A(module, key);
    uint proc = CalcProcHash(procedure, key);
    return FindAPI_MH(mod, proc, key);
}

__declspec(noinline)
void* FindAPI_W(uint16* module, byte* procedure)
{
    uint key  = 0xFFFFFFFF;
    uint mod  = CalcModHash_W(module, key);
    uint proc = CalcProcHash(procedure, key);
    return FindAPI_MH(mod, proc, key);
}

__declspec(noinline)
uint CalcModHash_A(byte* module, uint key)
{
#ifdef _WIN64
    return (uint)CalcModHash64_A(module, (uint64)key);
#elif _WIN32
    return (uint)CalcModHash32_A(module, (uint32)key);
#endif
}

__declspec(noinline)
uint CalcModHash_W(uint16* module, uint key)
{
#ifdef _WIN64
    return (uint)CalcModHash64_W(module, (uint64)key);
#elif _WIN32
    return (uint)CalcModHash32_W(module, (uint32)key);
#endif
}

__declspec(noinline)
uint CalcProcHash(byte* procedure, uint key)
{
#ifdef _WIN64
    return (uint)CalcProcHash64(procedure, (uint64)key);
#elif _WIN32
    return (uint)CalcProcHash32(procedure, (uint32)key);
#endif
}

__declspec(noinline)
PML* GetDefaultPML()
{
#ifdef _WIN64
    TEB* teb = (TEB*)__readgsqword(0x30);
#elif _WIN32
    TEB* teb = (TEB*)__readfsdword(0x18);
#endif
    PEB_LDR_DATA* ldr = teb->ProcessEnvironmentBlock->LDR;
    LIST_ENTRY* entry = &ldr->InMemoryOrderModuleList;
    return (PML*)((uintptr)entry - offsetof(PML, Links));
}

static uint calcSeedHash(uint key)
{
    uint  hash = key;
    byte* ptr  = (byte*)(&key);
    for (int i = 0; i < KEY_SIZE; i++)
    {
        hash = ror(hash, ROR_SEED);
        hash += *ptr;
        ptr++;
    }
    return hash;
}

static uint calcKeyHash(uint seed, uint key)
{
    uint  hash = seed;
    byte* ptr  = (byte*)(&key);
    for (int i = 0; i < KEY_SIZE; i++)
    {
        hash = ror(hash, ROR_KEY);
        hash += *ptr;
        ptr++;
    }
    return hash;
}

static uint ror(uint value, uint bits)
{
#ifdef _WIN64
    return value >> bits | value << (64 - bits);
#elif _WIN32
    return value >> bits | value << (32 - bits);
#endif
}

#define KEY_SIZE_32 4
#define ROR_BITS_32 4
#define ROR_SEED_32 (ROR_BITS_32 + 1)
#define ROR_KEY_32  (ROR_BITS_32 + 2)
#define ROR_MOD_32  (ROR_BITS_32 + 3)
#define ROR_PROC_32 (ROR_BITS_32 + 4)

static uint32 calcSeedHash32(uint32 key);
static uint32 calcKeyHash32(uint32 seed, uint32 key);
static uint32 ror32(uint32 value, uint32 bits);

__declspec(noinline)
uint32 CalcModHash32_A(byte* module, uint32 key)
{
    uint32 seedHash = calcSeedHash32(key);
    uint32 keyHash  = calcKeyHash32(seedHash, key);
    uint32 modHash  = seedHash;
    for (;;)
    {
        byte b = *module;
        if (b == 0x00)
        {
            break;
        }
        if (b >= 'a')
        {
            b -= 0x20;
        }
        modHash = ror32(modHash, ROR_MOD_32);
        modHash += b;
        modHash = ror32(modHash, ROR_MOD_32);
        modHash += 0;
        module++;
    }
    return seedHash + keyHash + modHash;
}

__declspec(noinline)
uint32 CalcModHash32_W(uint16* module, uint32 key)
{
    uint32 seedHash = calcSeedHash32(key);
    uint32 keyHash  = calcKeyHash32(seedHash, key);
    uint32 modHash  = seedHash;
    for (;;)
    {
        byte b0 = *(byte*)((uintptr)module + 0);
        byte b1 = *(byte*)((uintptr)module + 1);
        if (b0 == 0x00 && b1 == 0x00)
        {
            break;
        }
        if (b0 >= 'a')
        {
            b0 -= 0x20;
        }
        if (b1 >= 'a')
        {
            b1 -= 0x20;
        }
        modHash = ror32(modHash, ROR_MOD_32);
        modHash += b0;
        modHash = ror32(modHash, ROR_MOD_32);
        modHash += b1;
        module++;
    }
    return seedHash + keyHash + modHash;
}

__declspec(noinline)
uint32 CalcProcHash32(byte* procedure, uint32 key)
{
    uint32 seedHash = calcSeedHash32(key);
    uint32 keyHash  = calcKeyHash32(seedHash, key);
    uint32 procHash = seedHash;
    for (;;)
    {
        byte b = *procedure;
        if (b == 0x00)
        {
            break;
        }
        procHash = ror32(procHash, ROR_PROC_32);
        procHash += b;
        procedure++;
    }
    return seedHash + keyHash + procHash;
}

static uint32 calcSeedHash32(uint32 key)
{
    uint32 hash = key;
    byte*  ptr  = (byte*)(&key);
    for (int i = 0; i < KEY_SIZE_32; i++)
    {
        hash = ror32(hash, ROR_SEED_32);
        hash += *ptr;
        ptr++;
    }
    return hash;
}

static uint32 calcKeyHash32(uint32 seed, uint32 key)
{
    uint32 hash = seed;
    byte*  ptr  = (byte*)(&key);
    for (int i = 0; i < KEY_SIZE_32; i++)
    {
        hash = ror32(hash, ROR_KEY_32);
        hash += *ptr;
        ptr++;
    }
    return hash;
}

static uint32 ror32(uint32 value, uint32 bits)
{
    return value >> bits | value << (32 - bits);
}

#define KEY_SIZE_64 8
#define ROR_BITS_64 8
#define ROR_SEED_64 (ROR_BITS_64 + 1)
#define ROR_KEY_64  (ROR_BITS_64 + 2)
#define ROR_MOD_64  (ROR_BITS_64 + 3)
#define ROR_PROC_64 (ROR_BITS_64 + 4)

static uint64 calcSeedHash64(uint64 key);
static uint64 calcKeyHash64(uint64 seed, uint64 key);
static uint64 ror64(uint64 value, uint64 bits);

__declspec(noinline)
uint64 CalcModHash64_A(byte* module, uint64 key)
{
    uint64 seedHash = calcSeedHash64(key);
    uint64 keyHash  = calcKeyHash64(seedHash, key);
    uint64 modHash  = seedHash;
    for (;;)
    {
        byte b = *module;
        if (b == 0x00)
        {
            break;
        }
        if (b >= 'a')
        {
            b -= 0x20;
        }
        modHash = ror64(modHash, ROR_MOD_64);
        modHash += b;
        modHash = ror64(modHash, ROR_MOD_64);
        modHash += 0;
        module++;
    }
    return seedHash + keyHash + modHash;
}

__declspec(noinline)
uint64 CalcModHash64_W(uint16* module, uint64 key)
{
    uint64 seedHash = calcSeedHash64(key);
    uint64 keyHash  = calcKeyHash64(seedHash, key);
    uint64 modHash  = seedHash;
    for (;;)
    {
        byte b0 = *(byte*)((uintptr)module + 0);
        byte b1 = *(byte*)((uintptr)module + 1);
        if (b0 == 0x00 && b1 == 0x00)
        {
            break;
        }
        if (b0 >= 'a')
        {
            b0 -= 0x20;
        }
        if (b1 >= 'a')
        {
            b1 -= 0x20;
        }
        modHash = ror64(modHash, ROR_MOD_64);
        modHash += b0;
        modHash = ror64(modHash, ROR_MOD_64);
        modHash += b1;
        module++;
    }
    return seedHash + keyHash + modHash;
}

__declspec(noinline)
uint64 CalcProcHash64(byte* procedure, uint64 key)
{
    uint64 seedHash = calcSeedHash64(key);
    uint64 keyHash  = calcKeyHash64(seedHash, key);
    uint64 procHash = seedHash;
    for (;;)
    {
        byte b = *procedure;
        if (b == 0x00)
        {
            break;
        }
        procHash = ror64(procHash, ROR_PROC_64);
        procHash += b;
        procedure++;
    }
    return seedHash + keyHash + procHash;
}

static uint64 calcSeedHash64(uint64 key)
{
    uint64 hash = key;
    byte*  ptr  = (byte*)(&key);
    for (int i = 0; i < KEY_SIZE_64; i++)
    {
        hash = ror64(hash, ROR_SEED_64);
        hash += *ptr;
        ptr++;
    }
    return hash;
}

static uint64 calcKeyHash64(uint64 seed, uint64 key)
{
    uint64 hash = seed;
    byte*  ptr  = (byte*)(&key);
    for (int i = 0; i < KEY_SIZE_64; i++)
    {
        hash = ror64(hash, ROR_KEY_64);
        hash += *ptr;
        ptr++;
    }
    return hash;
}

static uint64 ror64(uint64 value, uint64 bits)
{
    return value >> bits | value << (64 - bits);
}
