#include "build.h"
#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "hash_api.h"
#include "rel_addr.h"
#include "random.h"
#include "crypto.h"
#include "errno.h"
#include "context.h"
#include "layout.h"
#include "ptr_table.h"
#include "win_base.h"
#include "debug.h"

typedef struct {
    // store options
    bool NotEraseInstruction;

    // API addresses
    MultiByteToWideChar_t MultiByteToWideChar;
    WideCharToMultiByte_t WideCharToMultiByte;

    // submodules method
    mt_malloc_t  malloc;
    mt_calloc_t  calloc;
    mt_realloc_t realloc;
    mt_free_t    free;
} WinBase;

// methods for user
UTF16 WB_ANSIToUTF16(ANSI s);
ANSI  WB_UTF16ToANSI(UTF16 s);
UTF16 WB_ANSIToUTF16N(ANSI s, int n);
ANSI  WB_UTF16ToANSIN(UTF16 s, int n);

// methods for runtime
errno WB_Uninstall();

static WinBase* getModulePointer();

static bool initModuleAPI(WinBase* module, Context* context);
static bool initModuleEnv(WinBase* module, Context* context);
static void eraseModuleMethod(Context* context);
static void setModulePointer(WinBase* module);

WinBase_M* InitWinBase(Context* context)
{
    // set structure address
    uintptr addr = context->MainMemPage;
    uintptr moduleAddr = addr + LAYOUT_WB_STRUCT + RandUintN(addr, 128);
    uintptr methodAddr = addr + LAYOUT_WB_METHOD + RandUintN(addr, 128);
    // allocate module memory
    WinBase* module = (WinBase*)moduleAddr;
    mem_init(module, sizeof(WinBase));
    // store options
    module->NotEraseInstruction = context->NotEraseInstruction;
    // initialize module
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initModuleAPI(module, context))
        {
            errno = ERR_WIN_BASE_INIT_API;
            break;
        }
        if (!initModuleEnv(module, context))
        {
            errno = ERR_WIN_BASE_INIT_ENV;
            break;
        }
        break;
    }
    eraseModuleMethod(context);
    if (errno != NO_ERROR)
    {
        SetLastErrno(errno);
        return NULL;
    }
    setModulePointer(module);
    // create method set
    WinBase_M* method = (WinBase_M*)methodAddr;
    method->ANSIToUTF16  = GetFuncAddr(&WB_ANSIToUTF16);
    method->UTF16ToANSI  = GetFuncAddr(&WB_UTF16ToANSI);
    method->ANSIToUTF16N = GetFuncAddr(&WB_ANSIToUTF16N);
    method->UTF16ToANSIN = GetFuncAddr(&WB_UTF16ToANSIN);
    method->Uninstall    = GetFuncAddr(&WB_Uninstall);
    return method;
}

static bool initModuleAPI(WinBase* module, Context* context)
{
    typedef struct {
        uint pHash; uint hKey; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x5A0BBE5359A272F2, 0xF434E337059CB0C7 }, // MultiByteToWideChar
        { 0x080448D6DB38EC1B, 0x3E5B3174E09112AB }, // WideCharToMultiByte
    };
#elif _WIN32
    {
        { 0xD20CFB1A, 0x7C7609D6 }, // MultiByteToWideChar
        { 0xD3DCEEA4, 0x7F287F6B }, // WideCharToMultiByte
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        winapi item = list[i];
        void*  proc = context->FindAPI_MA(context->hKernel32, item.pHash, item.hKey);
        if (proc == NULL)
        {
            return false;
        }
        list[i].proc = proc;
    }
    module->MultiByteToWideChar = list[0].proc;
    module->WideCharToMultiByte = list[1].proc;
    return true;
}

static bool initModuleEnv(WinBase* module, Context* context)
{
    module->malloc  = context->mt_malloc;
    module->calloc  = context->mt_calloc;
    module->realloc = context->mt_realloc;
    module->free    = context->mt_free;
    return true;
}

static void eraseModuleMethod(Context* context)
{
    if (context->NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&initModuleAPI));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseModuleMethod));
    uintptr size  = end - begin;
    EraseInstruction((void*)begin, size);
}

static void setModulePointer(WinBase* module)
{
    *(WinBase**)(POINTER_OFFSET_WIN_BASE) = module;
}

#pragma optimize("", off)
static WinBase* getModulePointer()
{
    return *(WinBase**)POINTER_OFFSET_WIN_BASE;
}
#pragma optimize("", on)

__declspec(noinline)
UTF16 WB_ANSIToUTF16(ANSI s)
{
    return WB_ANSIToUTF16N(s, -1);
}

__declspec(noinline)
ANSI WB_UTF16ToANSI(UTF16 s)
{
    return WB_UTF16ToANSIN(s, -1);
}

__declspec(noinline)
UTF16 WB_ANSIToUTF16N(ANSI s, int n)
{
    WinBase* module = getModulePointer();

    int len = module->MultiByteToWideChar(CP_ACP, 0, s, n, NULL, 0);
    if (len == 0)
    {
        return NULL;
    }
    UTF16 str = module->malloc((uint)(len * 2));
    if (str == NULL)
    {
        return NULL;
    }
    len = module->MultiByteToWideChar(CP_ACP, 0, s, n, str, len);
    if (len == 0)
    {
        module->free(str);
        return NULL;
    }
    return str;
}

__declspec(noinline)
ANSI WB_UTF16ToANSIN(UTF16 s, int n)
{
    WinBase* module = getModulePointer();

    int len = module->WideCharToMultiByte(CP_ACP, 0, s, n, NULL, 0, NULL, NULL);
    if (len == 0)
    {
        return NULL;
    }
    ANSI str = module->malloc(len);
    if (str == NULL)
    {
        return NULL;
    }
    len = module->WideCharToMultiByte(CP_ACP, 0, s, n, str, len, NULL, NULL);
    if (len == 0)
    {
        module->free(str);
        return NULL;
    }
    return str;
}

__declspec(noinline)
errno WB_Uninstall()
{
    return NO_ERROR;
}
