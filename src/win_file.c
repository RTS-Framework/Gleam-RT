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
#include "win_file.h"
#include "debug.h"

#ifdef SMALL_CHUNK_SIZE
    #define CHUNK_SIZE 64
#else
    #define CHUNK_SIZE 4096
#endif

typedef struct {
    // API address
    CreateFileA_t   CreateFileA;
    CreateFileW_t   CreateFileW;
    GetFileSizeEx_t GetFileSizeEx;
    ReadFile_t      ReadFile;
    WriteFile_t     WriteFile;
    CloseHandle_t   CloseHandle;

    // submodules method
    mt_malloc_t malloc;
    mt_free_t   free;
} WinFile;

// methods for user
errno WF_ReadFileA(LPSTR path, databuf* file);
errno WF_ReadFileW(LPWSTR path, databuf* file);
errno WF_WriteFileA(LPSTR path, databuf* file);
errno WF_WriteFileW(LPWSTR path, databuf* file);

// methods for runtime
errno WF_Uninstall();

static WinFile* getModulePointer();

static bool initModuleAPI(WinFile* module, Context* context);
static bool initModuleEnv(WinFile* module, Context* context);
static void eraseModuleMethod(Context* context);
static void setModulePointer(WinFile* module);

errno readFile(HANDLE hFile, databuf* file);
errno writeFile(HANDLE hFile, databuf* file);

WinFile_M* InitWinFile(Context* context)
{
    // set structure address
    uintptr addr = context->MainMemPage;
    uintptr moduleAddr = addr + LAYOUT_WF_STRUCT + RandUintN(0, 128);
    uintptr methodAddr = addr + LAYOUT_WF_METHOD + RandUintN(0, 128);
    // allocate module memory
    WinFile* module = (WinFile*)moduleAddr;
    mem_init(module, sizeof(WinFile));
    // initialize module
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initModuleAPI(module, context))
        {
            errno = ERR_WIN_FILE_INIT_API;
            break;
        }
        if (!initModuleEnv(module, context))
        {
            errno = ERR_WIN_FILE_INIT_ENV;
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
    WinFile_M* method = (WinFile_M*)methodAddr;
    method->ReadFileA  = GetFuncAddr(&WF_ReadFileA);
    method->ReadFileW  = GetFuncAddr(&WF_ReadFileW);
    method->WriteFileA = GetFuncAddr(&WF_WriteFileA);
    method->WriteFileW = GetFuncAddr(&WF_WriteFileW);
    method->Uninstall  = GetFuncAddr(&WF_Uninstall);
    return method;
}

__declspec(noinline)
static bool initModuleAPI(WinFile* module, Context* context)
{
    typedef struct {
        uint pHash; uint hKey; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0xB8051A7915B80944, 0x0F743D616B0CAEE6 }, // CreateFileA
        { 0x3735E419DDE43453, 0xE7876845E2EEE5F9 }, // CreateFileW
        { 0x19FA8270E3357B8E, 0xB404659651609EFC }, // GetFileSizeEx
        { 0x897FBABEB06C235B, 0xB850B555B85E70FB }, // ReadFile
        { 0xB88F4B527CFE51D5, 0x9F87323E42C1C109 }, // WriteFile
    };
#elif _WIN32
    {
        { 0x041548A2, 0x6078A702 }, // CreateFileA
        { 0xC144ECFB, 0x773BD184 }, // CreateFileW
        { 0xE65C60FB, 0x1B4E1DC2 }, // GetFileSizeEx
        { 0x9D073E4A, 0x3DA8E38C }, // ReadFile
        { 0x16637045, 0x522192A1 }, // WriteFile
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
    module->CreateFileA   = list[0].proc;
    module->CreateFileW   = list[1].proc;
    module->GetFileSizeEx = list[2].proc;
    module->ReadFile      = list[3].proc;
    module->WriteFile     = list[4].proc;

    module->CloseHandle = context->CloseHandle;

    // erase data in the large stack
    mem_init(list, sizeof(list));
    return true;
}

__declspec(noinline)
static bool initModuleEnv(WinFile* module, Context* context)
{
    module->malloc = context->mt_malloc;
    module->free   = context->mt_free;
    return true;
}

__declspec(noinline)
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

__declspec(noinline)
static void setModulePointer(WinFile* module)
{
    *(WinFile**)(POINTER_OFFSET_WIN_FILE) = module;
}

__declspec(noinline)
static WinFile* getModulePointer()
{
    return *(WinFile**)POINTER_OFFSET_WIN_FILE;
}

__declspec(noinline)
errno WF_ReadFileA(LPSTR path, databuf* file)
{
    WinFile* module = getModulePointer();

    HANDLE hFile = module->CreateFileA(
        path, GENERIC_READ, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return GetLastErrno();
    }
    return readFile(hFile, file);
}

__declspec(noinline)
errno WF_ReadFileW(LPWSTR path, databuf* file)
{
    WinFile* module = getModulePointer();

    HANDLE hFile = module->CreateFileW(
        path, GENERIC_READ, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return GetLastErrno();
    }
    return readFile(hFile, file);
}

__declspec(noinline)
errno WF_WriteFileA(LPSTR path, databuf* file)
{
    WinFile* module = getModulePointer();

    HANDLE hFile = module->CreateFileA(
        path, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return GetLastErrno();
    }
    return writeFile(hFile, file);
}

__declspec(noinline)
errno WF_WriteFileW(LPWSTR path, databuf* file)
{
    WinFile* module = getModulePointer();

    HANDLE hFile = module->CreateFileW(
        path, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return GetLastErrno();
    }
    return writeFile(hFile, file);
}

__declspec(noinline)
errno readFile(HANDLE hFile, databuf* file)
{
    WinFile* module = getModulePointer();

    int64 fSize  = 0;
    void* buffer = NULL;
    errno errno  = NO_ERROR;
    for (;;)
    {
        // get the file size
        if (!module->GetFileSizeEx(hFile, &fSize))
        {
            errno = GetLastErrno();
            break;
        }
        // allocate memory for store file
        byte* fBuf = module->malloc((uint)fSize);
        if (fBuf == NULL)
        {
            errno = GetLastErrno();
            break;
        }
        buffer = fBuf;
        // read file until EOF
        int64 read = 0;
        for (;;)
        {
            // prevent buffer overflow
            int64 chunkSize = CHUNK_SIZE;
            int64 remaining = fSize - read;
            if (remaining < chunkSize)
            {
                chunkSize = remaining;
            }
            // read file chunk
            DWORD n;
            if (!module->ReadFile(hFile, fBuf, (DWORD)chunkSize, &n, NULL))
            {
                errno = GetLastErrno();
                break;
            }
            // check is EOF
            if (n < chunkSize)
            {
                break;
            }
            read += n;
            if (read == fSize)
            {
                break;
            }
            // read next chunk
            fBuf += n;
        }
        break;
    }

    if (!module->CloseHandle(hFile) && errno == NO_ERROR)
    {
        errno = GetLastErrno();
    }
    if (errno != NO_ERROR)
    {
        module->free(buffer);
        return errno;
    }

    // write result
    file->buf = buffer;
    file->len = (uint)fSize;
    return NO_ERROR;
}

__declspec(noinline)
errno writeFile(HANDLE hFile, databuf* file)
{
    WinFile* module = getModulePointer();

    byte* buffer  = file->buf;
    uint  written = 0;
    errno errno   = NO_ERROR;
    for (;;)
    {
        // prevent buffer overflow
        uint chunkSize = CHUNK_SIZE;
        uint remaining = file->len - written;
        if (remaining < chunkSize)
        {
            chunkSize = remaining;
        }
        // write file chunk
        DWORD n;
        if (!module->WriteFile(hFile, buffer, (DWORD)chunkSize, &n, NULL))
        {
            errno = GetLastErrno();
            break;
        }
        // check is finished
        written += n;
        if (written == file->len)
        {
            break;
        }
        // write next chunk
        buffer += n;
    }

    if (!module->CloseHandle(hFile) && errno == NO_ERROR)
    {
        errno = GetLastErrno();
    }
    return errno;
}

__declspec(noinline)
errno WF_Uninstall()
{
    return NO_ERROR;
}
