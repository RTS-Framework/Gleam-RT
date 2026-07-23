#include "build.h"
#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "hash_api.h"
#include "rel_addr.h"
#include "random.h"
#include "crypto.h"
#include "errno.h"
#include "context.h"
#include "layout.h"
#include "ptr_table.h"
#include "mod_argument.h"
#include "debug.h"

// +--------+----------+--------+----------+
// | arg id | arg size | erased | arg data |
// +--------+----------+--------+----------+
// | uint32 |  uint32  |  bool  |   var    |
// +--------+----------+--------+----------+

#define OFFSET_ARGUMENT_DATA (4 + 4 + 1)

typedef struct {
    // API address
    VirtualAlloc_t        VirtualAlloc;
    VirtualFree_t         VirtualFree;
    ReleaseMutex_t        ReleaseMutex;
    WaitForSingleObject_t WaitForSingleObject;
    CloseHandle_t         CloseHandle;

    // store argument
    byte*  Address;
    uint   Size;
    uint32 NumArgs;
    HANDLE hMutex;

    byte Key[CRYPTO_KEY_SIZE];
    byte IV [CRYPTO_IV_SIZE];
} ArgumentStore;

// methods for upper module
BOOL AS_GetValue(uint32 id, void* value, uint32* size);
BOOL AS_GetPointer(uint32 id, void** pointer, uint32* size);
BOOL AS_Erase(uint32 id);
void AS_EraseAll();

// methods for runtime
bool  AS_Lock();
bool  AS_Unlock();
errno AS_Encrypt();
errno AS_Decrypt();
errno AS_Clean();

static ArgumentStore* getStorePointer();

static bool initStoreAPI(ArgumentStore* store, Context* context);
static bool initStoreEnv(ArgumentStore* store, Context* context);
static void eraseStoreMethod(Context* context);
static void cleanStoreResource(ArgumentStore* store);
static void setStorePointer(ArgumentStore* store);

static errno  loadArguments(ArgumentStore* store, Context* context);
static errno  shiftArguments(ArgumentStore* store, uint32 size);
static void   illuminateStub(byte* data, uint32 size, byte* key);
static void   decryptStub(byte* data, uint32 size, byte* key);
static void   initSBox(byte* sbox, uint64 seed);
static void   reverseSBox(byte* sbox);
static void   unshuffle(byte* data, uint32 size, uint64 seed);
static uint64 reverseXORShift64(uint64 seed);
static byte   ror(byte value, uint8 bits);
static byte   rol(byte value, uint8 bits);

ArgumentStore_M* InitArgumentStore(Context* context)
{
    // set structure address
    uintptr addr = context->MainMemPage;
    uintptr storeAddr  = addr + LAYOUT_AS_STRUCT + RandUintN(addr, 128);
    uintptr moduleAddr = addr + LAYOUT_AS_MODULE + RandUintN(addr, 128);
    // allocate store memory
    ArgumentStore* store = (ArgumentStore*)storeAddr;
    mem_init(store, sizeof(ArgumentStore));
    // initialize store
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initStoreAPI(store, context))
        {
            errno = ERR_ARGUMENT_INIT_API;
            break;
        }
        if (!initStoreEnv(store, context))
        {
            errno = ERR_ARGUMENT_INIT_ENV;
            break;
        }
        errno = loadArguments(store, context);
        if (errno != NO_ERROR)
        {
            break;
        }
        break;
    }
    eraseStoreMethod(context);
    if (errno != NO_ERROR)
    {
        cleanStoreResource(store);
        SetLastErrno(errno);
        return NULL;
    }
    setStorePointer(store);
    // create methods for store
    ArgumentStore_M* module = (ArgumentStore_M*)moduleAddr;
    // methods for upper module
    module->GetValue   = GetFuncAddr(&AS_GetValue);
    module->GetPointer = GetFuncAddr(&AS_GetPointer);
    module->Erase      = GetFuncAddr(&AS_Erase);
    module->EraseAll   = GetFuncAddr(&AS_EraseAll);
    // methods for runtime
    module->Lock    = GetFuncAddr(&AS_Lock);
    module->Unlock  = GetFuncAddr(&AS_Unlock);
    module->Encrypt = GetFuncAddr(&AS_Encrypt);
    module->Decrypt = GetFuncAddr(&AS_Decrypt);
    module->Clean   = GetFuncAddr(&AS_Clean);
    // data for sysmon
    module->hMutex = store->hMutex;
    return module;
}

__declspec(noinline)
static bool initStoreAPI(ArgumentStore* store, Context* context)
{
    store->VirtualAlloc        = context->VirtualAlloc;
    store->VirtualFree         = context->VirtualFree;
    store->ReleaseMutex        = context->ReleaseMutex;
    store->WaitForSingleObject = context->WaitForSingleObject;
    store->CloseHandle         = context->CloseHandle;
    return true;
}

static bool initStoreEnv(ArgumentStore* store, Context* context)
{
    // create global mutex
    HANDLE hMutex = context->CreateMutexA(NULL, false, NAME_RT_AS_MUTEX_GLOBAL);
    if (hMutex == NULL)
    {
        return false;
    }
    store->hMutex = hMutex;
    // set crypto context data
    RandBuffer(store->Key, CRYPTO_KEY_SIZE);
    RandBuffer(store->IV, CRYPTO_IV_SIZE);
    return true;
}

static errno loadArguments(ArgumentStore* store, Context* context)
{
    uintptr stub = (uintptr)(GetFuncAddr(&Argument_Stub));
    // decrypt argument header
    byte header[ARG_HEADER_SIZE];
    mem_copy(header, (byte*)stub, sizeof(header));
    byte* buf = header + 1 + ARG_CRYPTO_KEY_SIZE;
    uint  fsz = sizeof(uint16) + sizeof(uint32);
    byte* key = header + ARG_OFFSET_CRYPTO_KEY;
    XORBuffer(buf, fsz, key, ARG_CRYPTO_KEY_SIZE);
    uint16 num  = *(uint16*)(header + ARG_OFFSET_NUM_ARGS);
    uint32 size = *(uint32*)(header + ARG_OFFSET_ARGS_SIZE);
    // check the number of arguments
    if (num > ARG_MAX_NUM_ARGUMENTS)
    {
        return ERR_ARGUMENT_INVALID_NUM;
    }
    // allocate memory page for store them
    uint32 pageSize = (uint32)(context->MPS);
    uint32 memSize  = (((size + num) / pageSize) + 1) * pageSize;
    memSize += (1 + RandUint32N(0, 16)) * pageSize;
    DWORD type = MEM_COMMIT|MEM_RESERVE;
    byte* mem = store->VirtualAlloc(NULL, memSize, type, PAGE_READWRITE);
    if (mem == NULL)
    {
        return ERR_ARGUMENT_ALLOC_MEM;
    }
    store->Address = mem;
    store->Size    = memSize;
    store->NumArgs = num;
    // copy encrypted arguments to new memory page,
    // num is used to reserve memory for the erased
    // field about each arguments
    byte* src = (byte*)(stub + ARG_OFFSET_FIRST_ARG);
    byte* dst = mem + num;
    mem_copy(dst, src, size);
    // decrypted arguments
    if (size > ARG_ALGO_SWITCH_SIZE)
    {
        illuminateStub(dst, size, key);
    } else {
        decryptStub(dst, size, key);
    }
    // shift argument for set erased flag
    errno errno = shiftArguments(store, size);
    if (errno != NO_ERROR)
    {
        return errno;
    }
    // erase argument stub after decrypt
    if (!context->NotEraseInstruction)
    {
        EraseBuffer((byte*)stub, ARG_HEADER_SIZE + size);
        // set a flag that already erased;
        stub = 0x00;
    }
    dbg_log("[argument]", "mem page: 0x%zX", store->Address);
    dbg_log("[argument]", "num args: %zu", store->NumArgs);
    return NO_ERROR;
}

static errno shiftArguments(ArgumentStore* store, uint32 size)
{
    byte*  addr = store->Address;
    byte*  args = addr + store->NumArgs;
    uint32 rem  = size;
    for (uint32 i = 0; i < store->NumArgs; i++)
    {
        uint32 aid = *(uint32*)(args + 0);
        uint32 asz = *(uint32*)(args + 4);
        uint32 set = 4 + 4 + asz;
        if (set > rem)
        {
            return ERR_ARGUMENT_INVALID_SIZE;
        }
        byte* src = args + 4 + 4;
        mem_copy(addr + 0, &aid, sizeof(aid));
        mem_copy(addr + 4, &asz, sizeof(asz));
        mem_copy(addr + 9, src, asz);
        addr[8] = 0; // set erased flag
        addr += OFFSET_ARGUMENT_DATA + asz;
        args += set;
        rem  -= set;
    }
    return NO_ERROR;
}

__declspec(noinline)
static void illuminateStub(byte* data, uint32 size, byte* key)
{
    uint64 seed = *(uint64*)key;
    // generate S-box from seed
    byte sbox[256];
    initSBox(sbox, seed);
    reverseSBox(sbox);
    unshuffle(data, size, seed);
    // substitute data
    for (uint i = 0; i < size; i++)
    {
        data[i] = sbox[data[i]];
    }
}

__declspec(noinline)
static void decryptStub(byte* data, uint32 size, byte* key)
{
    uint32 last = *(uint32*)(key+0);
    uint32 ctr  = *(uint32*)(key+4);
    uint keyIdx = last % ARG_CRYPTO_KEY_SIZE;
    for (uint32 i = 0; i < size; i++)
    {
        byte b = *data;
        b = rol(b, (uint8)(last % 8));
        b -= (byte)(ctr ^ last);
        b ^= *(key + keyIdx);
        b = ror(b, (uint8)(last % 8));
        b ^= (byte)last;
        *data = b;
        // update key index
        keyIdx++;
        if (keyIdx >= ARG_CRYPTO_KEY_SIZE)
        {
            keyIdx = 0;
        }
        ctr++;
        last = XORShift32(last);
        // update address
        data++;
    }
}

static byte ror(byte value, uint8 bits)
{
    return value >> bits | value << (8 - bits);
}

static byte rol(byte value, uint8 bits)
{
    return value << bits | value >> (8 - bits);
}

__declspec(noinline)
static void eraseStoreMethod(Context* context)
{
    if (context->NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&initStoreAPI));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseStoreMethod));
    uintptr size  = end - begin;
    EraseInstruction((void*)begin, size);
}

__declspec(noinline)
static void cleanStoreResource(ArgumentStore* store)
{
    if (store->Address != NULL)
    {
        EraseBuffer(store->Address, (int64)(store->Size));
    }
    if (store->VirtualFree != NULL && store->Address != NULL)
    {
        store->VirtualFree(store->Address, 0, MEM_RELEASE);
    }
    if (store->CloseHandle != NULL && store->hMutex != NULL)
    {
        store->CloseHandle(store->hMutex);
    }
}

// the next functions until reverseXORShift64 will be linked
// to another modules, so must move these after eraseStoreMethod

#pragma optimize("", off)
static void initSBox(byte* sbox, uint64 seed)
{
    // initialize S-Box byte array
    for (int i = 0; i < 256; i++)
    {
        sbox[i] = (byte)i;
    }
    for (uint i = 255; i > 0; i--)
    {
        uint j = seed % (uint64)(i + 1);
        byte t = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = t;
        seed = XORShift64(seed);
    }
}
#pragma optimize("", on)

__declspec(noinline)
static void reverseSBox(byte* sbox)
{
    byte buf[256];
    mem_copy(buf, sbox, sizeof(buf));
    for (int i = 0; i < 256; i++)
    {
        sbox[buf[i]] = (byte)i;
    }
}

__declspec(noinline)
static void unshuffle(byte* data, uint32 size, uint64 seed)
{
    // advance to the final seed
    for (uint32 i = size - 1; i > 0; i--)
    {
        seed = XORShift64(seed);
    }
    for (uint i = 1; i < size; i++)
    {
        seed = reverseXORShift64(seed);
        uint j = seed % (uint64)(i + 1);
        byte t = data[i];
        data[i] = data[j];
        data[j] = t;
    }
}

__declspec(noinline)
static uint64 reverseXORShift64(uint64 seed)
{
    // reverse seed ^= seed << 17
    seed ^= seed << 17;
    seed ^= seed << 34;

    // reverse seed ^= seed >> 7
    seed ^= seed >> 7;
    seed ^= seed >> 14;
    seed ^= seed >> 28;
    seed ^= seed >> 56;

    // reverse seed ^= seed << 13
    seed ^= seed << 13;
    seed ^= seed << 26;
    seed ^= seed << 52;
    return seed;
}

__declspec(noinline)
static void setStorePointer(ArgumentStore* store)
{
    *(ArgumentStore**)(POINTER_OFFSET_ARGUMENT_STORE) = store;
}

__declspec(noinline)
static ArgumentStore* getStorePointer()
{
    return *(ArgumentStore**)POINTER_OFFSET_ARGUMENT_STORE;
}

__declspec(noinline)
BOOL AS_GetValue(uint32 id, void* value, uint32* size)
{
    ArgumentStore* store = getStorePointer();

    if (!AS_Lock())
    {
        return false;
    }

    // search the target argument with id
    byte* addr = store->Address;
    bool found = false;
    for (uint32 i = 0; i < store->NumArgs; i++)
    {
        uint32 aid = *(uint32*)(addr + 0);
        uint32 asz = *(uint32*)(addr + 4);
        if (aid != id)
        {
            addr += OFFSET_ARGUMENT_DATA + asz;
            continue;
        }
        // check argument is erased
        bool erased = *(bool*)(addr + 8);
        if (erased)
        {
            break;
        }
        // only receive argument size
        if (value == NULL)
        {
            *size = asz;
            found = true;
            break;
        }
        // copy argument data to value pointer
        void* src = addr + OFFSET_ARGUMENT_DATA;
        mem_copy(value, src, asz);
        // receive argument size
        if (size != NULL)
        {
            *size = asz;
        }
        found = true;
        break;
    }

    if (!AS_Unlock())
    {
        return false;
    }
    return found;
}

__declspec(noinline)
BOOL AS_GetPointer(uint32 id, void** pointer, uint32* size)
{
    ArgumentStore* store = getStorePointer();

    if (!AS_Lock())
    {
        return false;
    }

    // search the target argument with id
    byte* addr = store->Address;
    bool found = false;
    for (uint32 i = 0; i < store->NumArgs; i++)
    {
        uint32 aid = *(uint32*)(addr + 0);
        uint32 asz = *(uint32*)(addr + 4);
        if (aid != id)
        {
            addr += OFFSET_ARGUMENT_DATA + asz;
            continue;
        }
        // check argument is erased
        bool erased = *(bool*)(addr + 8);
        if (erased)
        {
            break;
        }
        // receive argument pointer
        if (asz != 0)
        {
            *pointer = (void*)(addr + OFFSET_ARGUMENT_DATA);
        } else {
            *pointer = NULL;
        }
        // receive argument size
        if (size != NULL)
        {
            *size = asz;
        }
        found = true;
        break;
    }

    if (!AS_Unlock())
    {
        return false;
    }
    return found;
}

__declspec(noinline)
BOOL AS_Erase(uint32 id)
{
    ArgumentStore* store = getStorePointer();

    if (!AS_Lock())
    {
        return false;
    }

    // search the target argument with id
    byte* addr = store->Address;
    bool found = false;
    for (uint32 i = 0; i < store->NumArgs; i++)
    {
        uint32 aid = *(uint32*)(addr + 0);
        uint32 asz = *(uint32*)(addr + 4);
        if (aid != id)
        {
            addr += OFFSET_ARGUMENT_DATA + asz;
            continue;
        }
        // check argument is erased
        bool* erased = (bool*)(addr + 8);
        if (*erased)
        {
            found = true;
            break;
        }
        // write the erased flag
        *erased = true;
        // erase argument data
        EraseBuffer(addr + OFFSET_ARGUMENT_DATA, (int64)asz);
        found = true;
        break;
    }

    if (!AS_Unlock())
    {
        return false;
    }
    return found;
}

__declspec(noinline)
void AS_EraseAll()
{
    ArgumentStore* store = getStorePointer();

    if (!AS_Lock())
    {
        return;
    }

    byte* addr = store->Address;
    for (uint32 i = 0; i < store->NumArgs; i++)
    {
        uint32 asz = *(uint32*)(addr + 4);
        // if not erased, overwrite it
        bool* erased = (bool*)(addr + 8);
        if (!*erased)
        {
            // write the erased flag
            *erased = true;
            // erase argument data
            EraseBuffer(addr + OFFSET_ARGUMENT_DATA, (int64)asz);
        }
        addr += OFFSET_ARGUMENT_DATA + asz;
    }

    AS_Unlock();
}

__declspec(noinline)
bool AS_Lock()
{
    ArgumentStore* store = getStorePointer();

    DWORD event = store->WaitForSingleObject(store->hMutex, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
bool AS_Unlock()
{
    ArgumentStore* store = getStorePointer();

    return store->ReleaseMutex(store->hMutex);
}

__declspec(noinline)
errno AS_Encrypt()
{
    ArgumentStore* store = getStorePointer();

    byte* key = store->Key;
    byte* iv  = store->IV;
    RandBuffer(key, CRYPTO_KEY_SIZE);
    RandBuffer(iv, CRYPTO_IV_SIZE);
    EncryptBuffer(store->Address, store->Size, key, iv);
    return NO_ERROR;
}

__declspec(noinline)
errno AS_Decrypt()
{
    ArgumentStore* store = getStorePointer();

    byte* key = store->Key;
    byte* iv  = store->IV;
    DecryptBuffer(store->Address, store->Size, key, iv);
    return NO_ERROR;
}

__declspec(noinline)
errno AS_Clean()
{
    ArgumentStore* store = getStorePointer();

    // erase all arguments
    EraseBuffer(store->Address, store->Size);

    errno errno = NO_ERROR;

    // free memory page
    if (!store->VirtualFree(store->Address, 0, MEM_RELEASE) && errno == NO_ERROR)
    {
        errno = ERR_ARGUMENT_FREE_MEM;
    }

    // close mutex
    if (!store->CloseHandle(store->hMutex) && errno == NO_ERROR)
    {
        errno = ERR_ARGUMENT_CLOSE_MUTEX;
    }
    return errno;
}
