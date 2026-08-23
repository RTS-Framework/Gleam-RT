#include "build.h"
#include "c_types.h"
#include "win_types.h"
#include "win_structs.h"
#include "dll_kernel32.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "lib_encode.h"
#include "lib_hash.h"
#include "hash_api.h"
#include "hash_mod.h"
#include "rel_addr.h"
#include "random.h"
#include "crypto.h"
#include "compress.h"
#include "serialize.h"
#include "mem_scanner.h"
#include "win_api.h"
#include "errno.h"
#include "context.h"
#include "layout.h"
#include "ptr_table.h"
#include "detector.h"
#include "mod_library.h"
#include "mod_memory.h"
#include "mod_thread.h"
#include "mod_resource.h"
#include "mod_argument.h"
#include "mod_storage.h"
#include "win_base.h"
#include "win_file.h"
#include "win_http.h"
#include "win_crypto.h"
#include "watchdog.h"
#include "sysmon.h"
#include "shield.h"
#include "option.h"
#include "runtime.h"
#include "debug.h"

// about Windows API redirector
typedef struct {
    void* src;
    void* dst;
} API_RDR;

typedef struct {
    // store options and information
    Runtime_Opts Options;
    Runtime_Info Info;

    // process environment
    PEB* PEB; // process environment block
    PML* PML; // process module list (snapshot)

    // process exe image base
    HMODULE ImageBase;

    // core dll address
    HMODULE hKernel32;
    HMODULE hNtdll;

    // API address
    GetSystemInfo_t          GetSystemInfo;
    GetTickCount_t           GetTickCount;
    LoadLibraryA_t           LoadLibraryA;
    FreeLibrary_t            FreeLibrary;
    GetProcAddress_t         GetProcAddress;
    VirtualAlloc_t           VirtualAlloc;
    VirtualFree_t            VirtualFree;
    VirtualProtect_t         VirtualProtect;
    VirtualQuery_t           VirtualQuery;
    FlushInstructionCache_t  FlushInstructionCache;
    SuspendThread_t          SuspendThread;
    ResumeThread_t           ResumeThread;
    GetThreadContext_t       GetThreadContext;
    ExitThread_t             ExitThread;
    CreateMutexA_t           CreateMutexA;
    ReleaseMutex_t           ReleaseMutex;
    CreateEventA_t           CreateEventA;
    SetEvent_t               SetEvent;
    CreateWaitableTimerA_t   CreateWaitableTimerA;
    SetWaitableTimer_t       SetWaitableTimer;
    WaitForSingleObject_t    WaitForSingleObject;
    WaitForMultipleObjects_t WaitForMultipleObjects;
    DuplicateHandle_t        DuplicateHandle;
    CloseHandle_t            CloseHandle;
    SetCurrentDirectoryA_t   SetCurrentDirectoryA;
    SetCurrentDirectoryW_t   SetCurrentDirectoryW;
    SetErrorMode_t           SetErrorMode;
    SleepEx_t                SleepEx;
    ExitProcess_t            ExitProcess;

    // runtime data
    void*  MainMemPage; // store all structures
    void*  Prologue;    // store instance start address
    void*  Epilogue;    // store instance end address
    uint32 InstSize;    // store instance size
    uint32 PageSize;    // for memory management
    HANDLE hMutex;      // global method mutex

    // environment data
    SYSTEM_INFO SysInfo;   // system information
    DWORD       InitTick;  // store initialize tick count
    UINT        ErrorMode; // record old error mode.

    // Windows API redirector
    API_RDR Kernel32RDR[63];
    API_RDR NtdllRDR   [05];

    // try to lock submodule mutex
    HANDLE ModMutexHandle[9];
    bool   ModMutexStatus[9];

    // runtime metric
    RT_Core   RMCore;
    RT_Proc   RMProc;
    RT_SleepM RMSleep;

    // security module
    Detector_M* Detector;

    // runtime submodule
    LibraryTracker_M*  LibraryTracker;
    MemoryTracker_M*   MemoryTracker;
    ThreadTracker_M*   ThreadTracker;
    ResourceTracker_M* ResourceTracker;
    ArgumentStore_M*   ArgumentStore;
    InMemoryStorage_M* InMemoryStorage;

    // high-level module
    WinBase_M*   WinBase;
    WinFile_M*   WinFile;
    WinHTTP_M*   WinHTTP;
    WinCrypto_M* WinCrypto;

    // reliability module
    Watchdog_M* Watchdog;
    Sysmon_M*   Sysmon;

    // suffix module
    Shield_M* Shield;

    // RuntimeM (module/method)
    Runtime_M* RuntimeM;
} Runtime;

// export methods about Runtime except Stub
void* RT_FindMod_MH(uint  module, uint key);
void* RT_FindAPI_MA(void* module, uint procedure, uint key);
void* RT_FindAPI_MH(uint  module, uint procedure, uint key);
void* RT_FindMod_MHL(PML* pml, uint  module, uint key);
void* RT_FindAPI_MAL(PML* pml, void* module, uint procedure, uint key);
void* RT_FindAPI_MHL(PML* pml, uint  module, uint procedure, uint key);
void* RT_FindMod_A(byte*   module);
void* RT_FindMod_W(uint16* module);
void* RT_FindAPI_A(byte*   module, byte* procedure);
void* RT_FindAPI_W(uint16* module, byte* procedure);

void* RT_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
void* RT_GetProcAddressEx(HMODULE hModule, LPCSTR lpProcName, BOOL redirect);
void* RT_GetProcAddressStub(HMODULE hModule, LPCSTR lpProcName, BOOL redirect);
void* RT_GetProcAddressRaw(HMODULE hModule, LPCSTR lpProcName);

TEB* RT_GetTEB();
PEB* RT_GetPEB();
PML* RT_GetPML();

HMODULE RT_GetMainEXE();
HMODULE RT_GetKernel32();
HMODULE RT_GetNtdll();

BOOL  RT_SetCurrentDirectoryA(LPSTR lpPathName);
BOOL  RT_SetCurrentDirectoryW(LPWSTR lpPathName);
UINT  RT_SetErrorMode(UINT uMode);
void  RT_Sleep(DWORD dwMilliseconds);
DWORD RT_SleepEx(DWORD dwMilliseconds, BOOL bAlertable);
void  RT_ExitProcess(UINT uExitCode);

errno RT_SleepHR(DWORD dwMilliseconds);
errno RT_Hide();
errno RT_Recover();
errno RT_GetOptions(Runtime_Opts* opts);
errno RT_GetRuntimeM(Runtime_M* rtm);
errno RT_GetInfo(Runtime_Info* info);
errno RT_GetMetrics(Runtime_Metrics* metrics);
errno RT_Cleanup();
errno RT_Exit();
void  RT_Stop(uint32 code);
errno RT_StopStub(bool exitThread, uint32 code);

// internal methods for Runtime submodules
void* RT_malloc(uint size);
void* RT_calloc(uint num, uint size);
void* RT_realloc(void* ptr, uint size);
bool  RT_free(void* ptr);
uint  RT_msize(void* ptr);
uint  RT_mcap(void* ptr);

errno RT_lock_mods();
errno RT_unlock_mods();
void  RT_try_lock_mods();
void  RT_try_unlock_mods();

bool RT_add_uptime(uint32 delta);
bool RT_set_health(bool healthy);

bool RT_flush_api_cache();

// HashAPI with spoof call (forge GetProcAddress)
void* SC_FindAPI_MA(void* module, uint procedure, uint key);
void* SC_FindAPI_MH(uint  module, uint procedure, uint key);
void* SC_FindAPI_MAL(PML* pml, void* module, uint procedure, uint key);
void* SC_FindAPI_MHL(PML* pml, uint  module, uint procedure, uint key);

// method wrapper for user and runtime submodules
SHA256* MW_SHA256New();
void    MW_SHA256Hash(void* data, uint len, byte (*hash)[32]);

void MW_SHA256_Write(SHA256* obj, void* data, uint len);
void MW_SHA256_Sum(SHA256* obj, byte (*hash)[32]);
void MW_SHA256_Reset(SHA256* obj);
void MW_SHA256_Free(SHA256* obj);

uint MW_Compress(void* dst, void* src, uint len, uint window, uint chain);

uint MW_MemScanByValue(void* value, uint size, uintptr* results, uint maxItem);
uint MW_MemScanByConfig(MemScan_Cfg* config, uintptr* results, uint maxItem);

// runtime internal methods
static Runtime* getRuntimePointer();

static bool rt_lock();
static bool rt_unlock();
static bool rt_try_lock();
static void rt_try_unlock();

static void  loadOptionFromStub(Runtime_Opts* opts);
static bool  checkOptionConflict(Runtime_Opts* opts);
static bool  isValidArgumentStub();
static PEB*  getPEBPointer();
static PML*  buildProcessModuleList(PEB* peb);
static void* getProcessImageBase(PEB* peb);
static bool  processImagePinning(PML* pml, HMODULE image, uint64 hash);
static void* getKernel32Address(PML* pml);
static void* getNtdllAddress(PML* pml);
static void* allocateMainMemoryPage(PML* pml, HMODULE kernel32);
static void  buildRuntimeInformation(Runtime* runtime);
static void* calculateEpilogue();

static bool  initRuntimeAPI(Runtime* runtime);
static bool  initRuntimeEnv(Runtime* runtime);
static bool  adjustPageProtect(Runtime* runtime, DWORD* old);
static bool  recoverPageProtect(Runtime* runtime, DWORD protect);
static void  setMainPagePointer(Runtime* runtime);
static void  setRuntimePointer(Runtime* runtime);
static errno initSubmodules(Runtime* runtime);
static errno initDetector(Runtime* runtime, Context* context);
static errno initLibraryTracker(Runtime* runtime, Context* context);
static errno initMemoryTracker(Runtime* runtime, Context* context);
static errno initThreadTracker(Runtime* runtime, Context* context);
static errno initResourceTracker(Runtime* runtime, Context* context);
static errno initArgumentStore(Runtime* runtime, Context* context);
static errno initInMemoryStorage(Runtime* runtime, Context* context);
static errno initWinBase(Runtime* runtime, Context* context);
static errno initWinFile(Runtime* runtime, Context* context);
static errno initWinHTTP(Runtime* runtime, Context* context);
static errno initWinCrypto(Runtime* runtime, Context* context);
static errno initWatchdog(Runtime* runtime, Context* context);
static errno initSysmon(Runtime* runtime, Context* context);
static errno initShield(Runtime* runtime, Context* context);
static bool  initAPIRedirector(Runtime* runtime);
static void  eraseArgumentStub(Runtime* runtime);
static void  eraseRuntimeMethod(Runtime* runtime);
static errno cleanRuntimeResource(Runtime* runtime, bool init);
static errno closeHandles(Runtime* runtime);
static void  interruptInit(Runtime* runtime);
static void  recoverProcessEnv(Runtime* runtime);
static void  recoverErrorMode(Runtime* runtime);
static void  cleanInitStack();

static void* getRuntimeMethods(LPCSTR lpProcName);
static void* getAPIRedirector(void* proc);
static void* getLazyAPIRedirector(HMODULE hModule, LPCSTR lpProcName);

static errno sleep(Runtime* runtime, uint32 milliseconds);
static errno hide(Runtime* runtime);
static errno recover(Runtime* runtime);

static void addPreSleepElapsed(int32 milliseconds);
static void addPostSleepElapsed(int32 milliseconds);

static void rs_erase(uintptr address, uintptr size);
static void rs_epilogue();

Runtime_M* InitRuntime(void* boot, Runtime_Opts* opts)
{
    if (!InitDebugger())
    {
        SetLastErrno(ERR_RUNTIME_INIT_DEBUGGER);
        return NULL;
    }
    // load runtime options
    Runtime_Opts opt;
    if (opts == NULL)
    {
        loadOptionFromStub(&opt);
        opts = &opt;
    }
    if (!checkOptionConflict(opts))
    {
        mem_init(&opt, sizeof(opt));
        SetLastErrno(ERR_RUNTIME_OPTION_CONFLICT);
        return NULL;
    }
    // check argument stub for calculate Epilogue
    if (!isValidArgumentStub())
    {
        mem_init(&opt, sizeof(opt));
        SetLastErrno(ERR_RUNTIME_INVALID_ARG_STUB);
        return NULL;
    }
    // prepare runtime basic environment
    PEB* PEB = getPEBPointer();
    PML* PML = buildProcessModuleList(PEB);
    // prepare process image base
    HMODULE imageBase = getProcessImageBase(PEB);
    // check image pinning hash
    if (!processImagePinning(PML, imageBase, opts->ImagePinningHash))
    {
        mem_init(&opt, sizeof(opt));
        SetLastErrno(ERR_RUNTIME_IMAGE_PINNING);
        return NULL;
    }
    // get kernel32.dll and ntdll.dll address
    HMODULE hKernel32 = getKernel32Address(PML);
    if (hKernel32 == NULL)
    {
        mem_init(&opt, sizeof(opt));
        SetLastErrno(ERR_RUNTIME_NO_KERNEL32_ADDR);
        return NULL;
    }
    HMODULE hNtdll = getNtdllAddress(PML);
    if (hNtdll == NULL)
    {
        mem_init(&opt, sizeof(opt));
        SetLastErrno(ERR_RUNTIME_NO_NTDLL_ADDR);
        return NULL;
    }
    // alloc memory for store runtime structure
    void* mainMemPage = allocateMainMemoryPage(PML, hKernel32);
    if (mainMemPage == NULL)
    {
        mem_init(&opt, sizeof(opt));
        SetLastErrno(ERR_RUNTIME_ALLOC_MAIN_MEM_PAGE);
        return NULL;
    }
    // set structure address
    uintptr addr = (uintptr)mainMemPage;
    uintptr runtimeAddr = addr + LAYOUT_RUNTIME_STRUCT + RandUintN(0, 128);
    uintptr moduleAddr  = addr + LAYOUT_RUNTIME_MODULE + RandUintN(0, 128);
    // initialize structure
    Runtime* runtime = (Runtime*)runtimeAddr;
    mem_init(runtime, sizeof(Runtime));
    // copy runtime option
    mem_copy(&runtime->Options, opts, sizeof(Runtime_Opts));
    // NOT use variable opts after this
    // MUST use runtime->Options.Field
    mem_init(&opt, sizeof(opt));
    // build runtime information
    buildRuntimeInformation(runtime);
    // store process environment
    runtime->PEB = PEB;
    runtime->PML = PML;
    // store process image base
    runtime->ImageBase = imageBase;
    // store core dll address
    runtime->hKernel32 = hKernel32;
    runtime->hNtdll    = hNtdll;
    // calculate the instance entry point
    uintptr bootAddr = (uintptr)(boot);
    uintptr initAddr = (uintptr)(GetFuncAddr(&InitRuntime));
    if (bootAddr == 0 || bootAddr > initAddr)
    {
        bootAddr = initAddr;
    }
    // set runtime data
    runtime->MainMemPage = mainMemPage;
    runtime->Prologue = (void*)bootAddr;
    runtime->Epilogue = calculateEpilogue();
    runtime->InstSize = (uint32)((uintptr)(runtime->Epilogue) - bootAddr);
    // initialize default value
    runtime->ErrorMode = (UINT)(-1);
    // initialize runtime
    DWORD oldProtect = 0;
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initRuntimeAPI(runtime))
        {
            errno = ERR_RUNTIME_INIT_API;
            break;
        }
        if (!initRuntimeEnv(runtime))
        {
            errno = ERR_RUNTIME_INIT_ENV;
            break;
        }
        if (!adjustPageProtect(runtime, &oldProtect))
        {
            errno = ERR_RUNTIME_ADJUST_PROTECT;
            break;
        }
        setMainPagePointer(runtime);
        setRuntimePointer(runtime);
        errno = initSubmodules(runtime);
        if (errno != NO_ERROR)
        {
            break;
        }
        if (!initAPIRedirector(runtime))
        {
            errno = ERR_RUNTIME_INIT_API_REDIRECTOR;
            break;
        }
        break;
    }
    // if failed to initialize runtime, erase argument stub.
    if (errno > ERR_RUNTIME_ADJUST_PROTECT || runtime->Options.NotAdjustProtect)
    {
        eraseArgumentStub(runtime);
    }
    if (errno == NO_ERROR || errno > ERR_RUNTIME_ADJUST_PROTECT)
    {
        eraseRuntimeMethod(runtime);
    }
    if (oldProtect != 0)
    {
        if (!recoverPageProtect(runtime, oldProtect) && errno == NO_ERROR)
        {
            errno = ERR_RUNTIME_RECOVER_PROTECT;
        }
    }
    // check initialize elapsed time is too long
    DWORD elapsed = runtime->GetTickCount() - runtime->InitTick;
    if (elapsed > 250)
    {
        errno = ERR_RUNTIME_INIT_TIMEOUT;
    }
    if (errno != NO_ERROR)
    {
        interruptInit(runtime);
        cleanRuntimeResource(runtime, true);
        cleanInitStack();
        SetLastErrno(errno);
        return NULL;
    }
    // compare the hash after initialized.
    if (runtime->Options.NotEraseInstruction)
    {
        // store the old hash before rebuild info
        byte hash[32];
        mem_copy(hash, runtime->Info.Hash, sizeof(hash));
        // calculate new hash and compare them
        buildRuntimeInformation(runtime);
        if (!mem_equal(hash, runtime->Info.Hash, sizeof(hash)))
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        // erase hash in stack
        mem_init(hash, sizeof(hash));
    }
    // update runtime metric
    runtime->RMCore.Uptime       = elapsed;
    runtime->RMCore.InitElapsed  = elapsed;
    runtime->RMCore.SecurityMode = runtime->Options.EnableSecurityMode;
    runtime->RMCore.IsHealthy    = true;
    // create methods for runtime
    Runtime_M* module = (Runtime_M*)moduleAddr;
    // hash api
    module->HashAPI.FindMod_MH  = GetFuncAddr(&RT_FindMod_MH);
    module->HashAPI.FindAPI_MA  = GetFuncAddr(&RT_FindAPI_MA);
    module->HashAPI.FindAPI_MH  = GetFuncAddr(&RT_FindAPI_MH);
    module->HashAPI.FindMod_MHL = GetFuncAddr(&RT_FindMod_MHL);
    module->HashAPI.FindAPI_MAL = GetFuncAddr(&RT_FindAPI_MAL);
    module->HashAPI.FindAPI_MHL = GetFuncAddr(&RT_FindAPI_MHL);
    module->HashAPI.FindMod_A   = GetFuncAddr(&RT_FindMod_A);
    module->HashAPI.FindMod_W   = GetFuncAddr(&RT_FindMod_W);
    module->HashAPI.FindAPI_A   = GetFuncAddr(&RT_FindAPI_A);
    module->HashAPI.FindAPI_W   = GetFuncAddr(&RT_FindAPI_W);
    // library tracker
    module->Library.LoadA   = runtime->LibraryTracker->LoadLibraryA;
    module->Library.LoadW   = runtime->LibraryTracker->LoadLibraryW;
    module->Library.LoadExA = runtime->LibraryTracker->LoadLibraryExA;
    module->Library.LoadExW = runtime->LibraryTracker->LoadLibraryExW;
    module->Library.Free    = runtime->LibraryTracker->FreeLibrary;
    module->Library.GetProc = GetFuncAddr(&RT_GetProcAddress);
    module->Library.Lock    = runtime->LibraryTracker->LockModule;
    module->Library.Unlock  = runtime->LibraryTracker->UnlockModule;
    module->Library.Status  = runtime->LibraryTracker->GetStatus;
    module->Library.FreeAll = runtime->LibraryTracker->FreeAllMu;
    // memory tracker
    module->Memory.Alloc   = runtime->MemoryTracker->Alloc;
    module->Memory.Calloc  = runtime->MemoryTracker->Calloc;
    module->Memory.Realloc = runtime->MemoryTracker->Realloc;
    module->Memory.Free    = runtime->MemoryTracker->Free;
    module->Memory.Size    = runtime->MemoryTracker->Size;
    module->Memory.Cap     = runtime->MemoryTracker->Cap;
    module->Memory.Lock    = runtime->MemoryTracker->LockRegion;
    module->Memory.Unlock  = runtime->MemoryTracker->UnlockRegion;
    module->Memory.Status  = runtime->MemoryTracker->GetStatus;
    module->Memory.FreeAll = runtime->MemoryTracker->FreeAllMu;
    // thread tracker
    module->Thread.New     = runtime->ThreadTracker->New;
    module->Thread.Exit    = runtime->ThreadTracker->Exit;
    module->Thread.Sleep   = runtime->ThreadTracker->Sleep;
    module->Thread.Lock    = runtime->ThreadTracker->LockThread;
    module->Thread.Unlock  = runtime->ThreadTracker->UnlockThread;
    module->Thread.Status  = runtime->ThreadTracker->GetStatus;
    module->Thread.KillAll = runtime->ThreadTracker->KillAllMu;
    // resource tracker
    module->Resource.LockMutex           = runtime->ResourceTracker->LockMutex;
    module->Resource.UnlockMutex         = runtime->ResourceTracker->UnlockMutex;
    module->Resource.LockEvent           = runtime->ResourceTracker->LockEvent;
    module->Resource.UnlockEvent         = runtime->ResourceTracker->UnlockEvent;
    module->Resource.LockSemaphore       = runtime->ResourceTracker->LockSemaphore;
    module->Resource.UnlockSemaphore     = runtime->ResourceTracker->UnlockSemaphore;
    module->Resource.LockWaitableTimer   = runtime->ResourceTracker->LockWaitableTimer;
    module->Resource.UnlockWaitableTimer = runtime->ResourceTracker->UnlockWaitableTimer;
    module->Resource.LockFile            = runtime->ResourceTracker->LockFile;
    module->Resource.UnlockFile          = runtime->ResourceTracker->UnlockFile;
    module->Resource.Status              = runtime->ResourceTracker->GetStatus;
    module->Resource.FreeAll             = runtime->ResourceTracker->FreeAllMu;
    // argument store
    module->Argument.GetValue   = runtime->ArgumentStore->GetValue;
    module->Argument.GetPointer = runtime->ArgumentStore->GetPointer;
    module->Argument.Erase      = runtime->ArgumentStore->Erase;
    module->Argument.EraseAll   = runtime->ArgumentStore->EraseAll;
    module->Argument.Status     = runtime->ArgumentStore->GetStatus;
    // in-memory storage
    module->Storage.SetValue   = runtime->InMemoryStorage->SetValue;
    module->Storage.GetValue   = runtime->InMemoryStorage->GetValue;
    module->Storage.GetPointer = runtime->InMemoryStorage->GetPointer;
    module->Storage.Delete     = runtime->InMemoryStorage->Delete;
    module->Storage.DeleteAll  = runtime->InMemoryStorage->DeleteAll;
    module->Storage.Status     = runtime->InMemoryStorage->GetStatus;
    // WinBase
    module->WinBase.ANSIToUTF16  = runtime->WinBase->ANSIToUTF16;
    module->WinBase.UTF16ToANSI  = runtime->WinBase->UTF16ToANSI;
    module->WinBase.ANSIToUTF16N = runtime->WinBase->ANSIToUTF16N;
    module->WinBase.UTF16ToANSIN = runtime->WinBase->UTF16ToANSIN;
    // WinFile
    module->WinFile.ReadFileA  = runtime->WinFile->ReadFileA;
    module->WinFile.ReadFileW  = runtime->WinFile->ReadFileW;
    module->WinFile.WriteFileA = runtime->WinFile->WriteFileA;
    module->WinFile.WriteFileW = runtime->WinFile->WriteFileW;
    // WinHTTP
    module->WinHTTP.Init    = runtime->WinHTTP->Init;
    module->WinHTTP.Get     = runtime->WinHTTP->Get;
    module->WinHTTP.Post    = runtime->WinHTTP->Post;
    module->WinHTTP.Do      = runtime->WinHTTP->Do;
    module->WinHTTP.FreeDLL = runtime->WinHTTP->FreeDLL;
    // WinCrypto
    module->WinCrypto.RandBuffer = runtime->WinCrypto->RandBuffer;
    module->WinCrypto.Hash       = runtime->WinCrypto->Hash;
    module->WinCrypto.HMAC       = runtime->WinCrypto->HMAC;
    module->WinCrypto.AESEncrypt = runtime->WinCrypto->AESEncrypt;
    module->WinCrypto.AESDecrypt = runtime->WinCrypto->AESDecrypt;
    module->WinCrypto.RSAGenKey  = runtime->WinCrypto->RSAGenKey;
    module->WinCrypto.RSAPubKey  = runtime->WinCrypto->RSAPubKey;
    module->WinCrypto.RSASign    = runtime->WinCrypto->RSASign;
    module->WinCrypto.RSAVerify  = runtime->WinCrypto->RSAVerify;
    module->WinCrypto.RSAEncrypt = runtime->WinCrypto->RSAEncrypt;
    module->WinCrypto.RSADecrypt = runtime->WinCrypto->RSADecrypt;
    module->WinCrypto.FreeDLL    = runtime->WinCrypto->FreeDLL;
    // random module
    module->Random.Seed     = GetFuncAddr(&GenerateSeed);
    module->Random.Int      = GetFuncAddr(&RandInt);
    module->Random.Int8     = GetFuncAddr(&RandInt8);
    module->Random.Int16    = GetFuncAddr(&RandInt16);
    module->Random.Int32    = GetFuncAddr(&RandInt32);
    module->Random.Int64    = GetFuncAddr(&RandInt64);
    module->Random.Uint     = GetFuncAddr(&RandUint);
    module->Random.Uint8    = GetFuncAddr(&RandUint8);
    module->Random.Uint16   = GetFuncAddr(&RandUint16);
    module->Random.Uint32   = GetFuncAddr(&RandUint32);
    module->Random.Uint64   = GetFuncAddr(&RandUint64);
    module->Random.IntN     = GetFuncAddr(&RandIntN);
    module->Random.Int8N    = GetFuncAddr(&RandInt8N);
    module->Random.Int16N   = GetFuncAddr(&RandInt16N);
    module->Random.Int32N   = GetFuncAddr(&RandInt32N);
    module->Random.Int64N   = GetFuncAddr(&RandInt64N);
    module->Random.UintN    = GetFuncAddr(&RandUintN);
    module->Random.Uint8N   = GetFuncAddr(&RandUint8N);
    module->Random.Uint16N  = GetFuncAddr(&RandUint16N);
    module->Random.Uint32N  = GetFuncAddr(&RandUint32N);
    module->Random.Uint64N  = GetFuncAddr(&RandUint64N);
    module->Random.Byte     = GetFuncAddr(&RandByte);
    module->Random.Bool     = GetFuncAddr(&RandBool);
    module->Random.BOOL     = GetFuncAddr(&RandBOOL);
    module->Random.Buffer   = GetFuncAddr(&RandBuffer);
    module->Random.Sequence = GetFuncAddr(&RandSequence);
    // encoding module
    module->Encoding.Hex.Encode = GetFuncAddr(&Hex_Encode);
    module->Encoding.Hex.Decode = GetFuncAddr(&Hex_Decode);
    module->Encoding.Base64.Encode = GetFuncAddr(&Base64_Encode);
    module->Encoding.Base64.Decode = GetFuncAddr(&Base64_Decode);
    // hash module
    module->Hash.SHA256.New  = GetFuncAddr(&MW_SHA256New);
    module->Hash.SHA256.Hash = GetFuncAddr(&MW_SHA256Hash);
    // crypto module
    module->Crypto.XORBuffer        = GetFuncAddr(&XORBuffer);
    module->Crypto.SubstituteBuffer = GetFuncAddr(&SubstituteBuffer);
    module->Crypto.ShuffleBuffer    = GetFuncAddr(&ShuffleBuffer);
    module->Crypto.EraseBuffer      = GetFuncAddr(&EraseBuffer);
    module->Crypto.EraseInstruction = GetFuncAddr(&EraseInstruction);
    // compress module
    module->Compressor.Compress   = GetFuncAddr(&MW_Compress);
    module->Compressor.Decompress = GetFuncAddr(&Decompress);
    // serialization module
    module->Serialization.Serialize   = GetFuncAddr(&Serialize);
    module->Serialization.Unserialize = GetFuncAddr(&Unserialize);
    // memory scanner
    module->MemScanner.ScanByValue  = GetFuncAddr(&MW_MemScanByValue);
    module->MemScanner.ScanByConfig = GetFuncAddr(&MW_MemScanByConfig);
    module->MemScanner.BinToPattern = GetFuncAddr(&BinToPattern);
    // about detector
    module->Detector.Detect = runtime->Detector->Detect;
    module->Detector.Status = runtime->Detector->GetStatus;
    // about watchdog
    module->Watchdog.SetHandler = runtime->Watchdog->SetHandler;
    module->Watchdog.SetTimeout = runtime->Watchdog->SetTimeout;
    module->Watchdog.Kick       = runtime->Watchdog->Kick;
    module->Watchdog.Enable     = runtime->Watchdog->Enable;
    module->Watchdog.Disable    = runtime->Watchdog->Disable;
    module->Watchdog.IsEnabled  = runtime->Watchdog->IsEnabled;
    module->Watchdog.Status     = runtime->Watchdog->GetStatus;
    module->Watchdog._Pause     = runtime->Watchdog->Pause;
    module->Watchdog._Continue  = runtime->Watchdog->Continue;
    // about system monitor
    module->Sysmon.Status    = runtime->Sysmon->GetStatus;
    module->Sysmon._Pause    = runtime->Sysmon->Pause;
    module->Sysmon._Continue = runtime->Sysmon->Continue;
    // about shield
    module->Shield.Status = runtime->Shield->GetStatus;
    module->Shield._Sleep = runtime->Shield->Sleep;
    module->Shield._Stop  = runtime->Shield->Stop;
    // about process environment
    module->Env.TEB = GetFuncAddr(&RT_GetTEB);
    module->Env.PEB = GetFuncAddr(&RT_GetPEB);
    module->Env.PML = GetFuncAddr(&RT_GetPML);
    // about immutable module handle
    module->DLL.MainEXE  = GetFuncAddr(&RT_GetMainEXE);
    module->DLL.Kernel32 = GetFuncAddr(&RT_GetKernel32);
    module->DLL.Ntdll    = GetFuncAddr(&RT_GetNtdll);
    // {THE TRUTH OF THE WORLD} && [THE END OF THE WORLD] :(
    module->Raw.GetProcAddress = GetFuncAddr(&RT_GetProcAddressRaw);
    module->Raw.ExitProcess    = GetFuncAddr(&RT_ExitProcess);
    // runtime core methods
    module->Core.Sleep   = GetFuncAddr(&RT_SleepHR);
    module->Core.Hide    = GetFuncAddr(&RT_Hide);
    module->Core.Recover = GetFuncAddr(&RT_Recover);
    module->Core.Options = GetFuncAddr(&RT_GetOptions);
    module->Core.Info    = GetFuncAddr(&RT_GetInfo);
    module->Core.Metrics = GetFuncAddr(&RT_GetMetrics);
    module->Core.Cleanup = GetFuncAddr(&RT_Cleanup);
    module->Core.Exit    = GetFuncAddr(&RT_Exit);
    module->Core.Stop    = GetFuncAddr(&RT_Stop);
    // runtime core data
    module->Data.Mutex = runtime->hMutex;
    // copy M pointer to runtime
    runtime->RuntimeM = module;
    cleanInitStack();
    return module;
}

static void loadOptionFromStub(Runtime_Opts* opts)
{
    // get option stub address
    uintptr stub = (uintptr)(GetFuncAddr(&Option_Stub));
    // copy runtime options from stub
    byte data[OPTION_STUB_SIZE];
    mem_copy(data, (byte*)stub, sizeof(data));
    // decrypt option data
    byte* dst = (byte*)((uintptr)data + 1 + OPTION_KEY_SIZE);
    uint  len = OPTION_STUB_SIZE - (1 + OPTION_KEY_SIZE);
    byte* key = (byte*)(stub + 1);
    XORBuffer(dst, len, key, OPTION_KEY_SIZE);
    // apply the option data
    // code about "*(byte*)(data + OPT_OFFSET_XXX) == 0" is special case
    opts->ImagePinningHash  = *(uint64*)(data + OPT_OFFSET_IMAGE_PINNING_HASH);
    opts->ShieldModuleHash  = *(uint64*)(data + OPT_OFFSET_SHIELD_MODULE_HASH);
    opts->ShieldEntryPoint  = *(uint64*)(data + OPT_OFFSET_SHIELD_ENTRY_POINT);
    opts->ShieldMemAddress  = *(uint64*)(data + OPT_OFFSET_SHIELD_MEM_ADDRESS);
    opts->EnableSecurityMode  = *(byte*)(data + OPT_OFFSET_ENABLE_SECURITY_MODE) == 0;
    opts->DisableDetector     = *(byte*)(data + OPT_OFFSET_DISABLE_DETECTOR) == 0;
    opts->DisableWatchdog     = *(byte*)(data + OPT_OFFSET_DISABLE_WATCHDOG) == 0;
    opts->DisableSysmon       = *(byte*)(data + OPT_OFFSET_DISABLE_SYSMON) == 0;
    opts->NotEraseInstruction = *(byte*)(data + OPT_OFFSET_NOT_ERASE_INSTRUCTION) == 0;
    opts->NotAdjustProtect    = *(byte*)(data + OPT_OFFSET_NOT_ADJUST_PROTECT) == 0;
    opts->TrackCurrentThread  = *(byte*)(data + OPT_OFFSET_TRACK_CURRENT_THREAD) == 0;
    // erase data in the large stack
    mem_init(data, sizeof(data));
}

static bool checkOptionConflict(Runtime_Opts* opts)
{
    if (opts->ShieldModuleHash != 0)
    {
        if (opts->ShieldEntryPoint == 0)
        {
            return false;
        }
        if (opts->ShieldMemAddress != 0)
        {
            return false;
        }
    }
    if (opts->ShieldModuleHash == 0 && opts->ShieldEntryPoint != 0)
    {
        return false;
    }
    return true;
}

static bool isValidArgumentStub()
{
    uintptr stub = (uintptr)(GetFuncAddr(&Argument_Stub));
    // check is already initialized
    if (*(byte*)stub == 0x00)
    {
        return false;
    }
    // decrypt argument header
    byte header[ARG_HEADER_SIZE];
    mem_init(header, sizeof(header));
    mem_copy(header, (byte*)stub, sizeof(header));
    byte* buf = header + 1 + ARG_CRYPTO_KEY_SIZE;
    uint  fsz = sizeof(uint16) + sizeof(uint32);
    byte* key = header + ARG_OFFSET_CRYPTO_KEY;
    XORBuffer(buf, fsz, key, ARG_CRYPTO_KEY_SIZE);
    // parse stub fields
    uint16 numArgs  = *(uint16*)(header + ARG_OFFSET_NUM_ARGS);
    uint32 argsSize = *(uint32*)(header + ARG_OFFSET_ARGS_SIZE);
    uint32 checksum = *(uint32*)(header + ARG_OFFSET_CHECKSUM);
    // erase data in the large stack
    mem_init(header, sizeof(header));
    // check the number of argument
    if (numArgs > ARG_MAX_NUM_ARGUMENTS)
    {
        return false;
    }
    // check argument checksum
    byte*  arg = (byte*)(stub + ARG_OFFSET_FIRST_ARG);
    uint32 crc = 0xFFFFFFFF;
    for (uint32 i = 0; i < argsSize; i++)
    {
        crc ^= (uint32)(arg[i]);
        for (int j = 0; j < 8; j++)
        {
            if ((crc & 1) != 0)
            {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^= 0xFFFFFFFF;
    return crc == checksum;
}

static uint32 calcArgumentStubSize()
{
    uintptr stub = (uintptr)(GetFuncAddr(&Argument_Stub));
    byte header[ARG_HEADER_SIZE];
    mem_init(header, sizeof(header));
    mem_copy(header, (byte*)stub, sizeof(header));
    byte* buf = header + 1 + ARG_CRYPTO_KEY_SIZE;
    uint  fsz = sizeof(uint16) + sizeof(uint32);
    byte* key = header + ARG_OFFSET_CRYPTO_KEY;
    XORBuffer(buf, fsz, key, ARG_CRYPTO_KEY_SIZE);
    uint32 argsSize = *(uint32*)(header + ARG_OFFSET_ARGS_SIZE);
    // erase data in the large stack
    mem_init(header, sizeof(header));
    return ARG_HEADER_SIZE + argsSize;
}

static PEB* getPEBPointer()
{
#ifdef _WIN64
    TEB* teb = (TEB*)__readgsqword(0x30);
#elif _WIN32
    TEB* teb = (TEB*)__readfsdword(0x18);
#endif
    return teb->ProcessEnvironmentBlock;
}

static PML* buildProcessModuleList(PEB* peb)
{
    PEB_LDR_DATA* ldr = peb->LDR;
    LIST_ENTRY* entry = &ldr->InMemoryOrderModuleList;
    return (PML*)((uintptr)entry - offsetof(PML, Links));
}

static void* getProcessImageBase(PEB* peb)
{
    return peb->ImageBaseAddress;
}

static bool processImagePinning(PML* pml, HMODULE image, uint64 hash)
{
    if (hash == 0)
    {
        return true;
    }
    LIST_ENTRY* head = &pml->Links;
    for (LIST_ENTRY* link = head->Flink; link != head; link = link->Flink)
    {
        PML* entry = (PML*)((uintptr)(link)-offsetof(PML, Links));
        if (entry->ImageBase != image)
        {
            continue;
        }
        UNICODE_STRING name = entry->BaseName;
        return HashMod(name.Buffer, name.Length) == hash;
    }
    return false;
}

static void* getKernel32Address(PML* pml)
{
#ifdef _WIN64
    uint mHash = 0x81281D579CF95014;
    uint hKey  = 0x17525CC1E154BA98;
#elif _WIN32
    uint mHash = 0x48CAA960;
    uint hKey  = 0x54FE3C56;
#endif
    return FindMod_MHL(pml, mHash, hKey);
}

static void* getNtdllAddress(PML* pml)
{
#ifdef _WIN64
    uint mHash = 0x3CCA726C479AD6EE;
    uint hKey  = 0xD2E8220B9E91AB06;
#elif _WIN32
    uint mHash = 0x49F19F51;
    uint hKey  = 0x5B0571BF;
#endif
    return FindMod_MHL(pml, mHash, hKey);
}

static void* allocateMainMemoryPage(PML* pml, HMODULE kernel32)
{
#ifdef _WIN64
    uint pHash = 0xAA8D188A1F0862DC;
    uint hKey  = 0x6EDC8B580ACA6913;
#elif _WIN32
    uint pHash = 0xA7CFDD6F;
    uint hKey  = 0x0F2BB61F;
#endif
    VirtualAlloc_t virtualAlloc = FindAPI_MAL(pml, kernel32, pHash, hKey);
    if (virtualAlloc == NULL)
    {
        return NULL;
    }
    SIZE_T size = MAIN_MEM_PAGE_SIZE + (1 + RandUintN(0, 32)) * 1024;
    DWORD  type = MEM_COMMIT|MEM_RESERVE;
    LPVOID addr = virtualAlloc(NULL, size, type, PAGE_READWRITE);
    if (addr == NULL)
    {
        return NULL;
    }
    // padding random data to main memory page
    uint range = RandUintN(0, (size - MAIN_MEM_PAGE_SIZE) / 5);
    RandBuffer(addr, MAIN_MEM_PAGE_SIZE + range);
    dbg_log("[runtime]", "Main Memory Page: 0x%zX", addr);
    return addr;
}

static void buildRuntimeInformation(Runtime* runtime)
{
    Runtime_Info* info = &runtime->Info;

    // calculate runtime .text size
    uintptr begin = (uintptr)(GetFuncAddr(&InitRuntime));
    uintptr end   = (uintptr)(GetFuncAddr(&Shield_Stub));
    uintptr size  = end - begin;

    // calculate runtime .text hash
    SHA256_Ctx ctx;
    SHA256_Init(&ctx);
    SHA256_Write(&ctx, (byte*)begin, size);
    SHA256_Sum(&ctx, &info->Hash);

    // update information fields
    info->Version = RUNTIME_VERSION;
    info->Size    = (uint32)size;
    info->Flags   = 0;

    // erase data in the large stack
    mem_init(&ctx, sizeof(ctx));
}

static void* calculateEpilogue()
{
    uintptr stub = (uintptr)(GetFuncAddr(&Argument_Stub));
    uint32  size = calcArgumentStubSize();
    return (void*)(stub + size);
}

static bool initRuntimeAPI(Runtime* runtime)
{
    typedef struct {
        uint pHash; uint hKey; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x86A86D57C8A841B1, 0x17525CC1E154BA98 }, // GetSystemInfo
        { 0x77F988FFD6E5F17B, 0xBCCCFEDA4ECB5CB5 }, // GetTickCount
        { 0xB726BDCEE213B000, 0xBC41C33EE9102207 }, // LoadLibraryA
        { 0x715D0BA3A37704ED, 0xF5E8C64F2FD1E69A }, // FreeLibrary
        { 0x1E1187BF74A001D9, 0x2457B30C5AFA694C }, // GetProcAddress
        { 0x447B8E23EA19AFBF, 0xC733FDBD9B57119F }, // VirtualAlloc
        { 0x66E51926BF5C2675, 0xE23E338B794BD214 }, // VirtualFree
        { 0xE720DBF70F19D718, 0xFD32DE1953F12824 }, // VirtualProtect
        { 0x6BFCB0DC860C2060, 0xB7AE04F1641B5A9E }, // VirtualQuery
        { 0x06172C4E43D310FB, 0xF2B7646EDF1ADF06 }, // FlushInstructionCache
        { 0xFC8825DC3C55B265, 0xCCBCA1685F8E8AD6 }, // SuspendThread
        { 0xB0CAB85785F06761, 0xF5EE69828D2BD6E1 }, // ResumeThread
        { 0x07752F687020ED8D, 0xFEB03CCC4111D6D3 }, // GetThreadContext
        { 0x9AD093D6D3F3F010, 0xE78BBF9830AA8844 }, // ExitThread
        { 0x1201412A13AA4E6F, 0x7275A1F15DD85A1F }, // CreateMutexA
        { 0x34B5B1C885933D84, 0xE2276FF8F3AD2105 }, // ReleaseMutex
        { 0xEC2E1ED137A9FC13, 0x0AB8729A0AA907A5 }, // CreateEventA
        { 0xB21BF291AD8FCA39, 0xFE54EB09C78288C7 }, // SetEvent
        { 0xE28EEE755182BA08, 0xD80628473A8AC9D2 }, // CreateWaitableTimerA
        { 0x5EA44B4FC8403DDC, 0xEB2D517E67A9A193 }, // SetWaitableTimer
        { 0x023C544BECCF303A, 0x70BE40CC74D98FA5 }, // WaitForSingleObject
        { 0xAA914C97CF93C6C4, 0xEBD4EB0F98F02345 }, // WaitForMultipleObjects
        { 0x8C0157728DBBDF00, 0x72A6D14AD23E4170 }, // DuplicateHandle
        { 0xAD3CAC3CA6B3F85F, 0x3A69E267838CC49B }, // CloseHandle
        { 0x7958DD2E625BFB9A, 0x8D88DDA980B5423A }, // SetCurrentDirectoryA
        { 0x92705193BA8D0E4C, 0x0157A58CBD86F5CB }, // SetCurrentDirectoryW
        { 0x47600C16911CFF63, 0xA1BAB93C34930F17 }, // SetErrorMode
        { 0xFF59A6239E10D034, 0x259506B04B900790 }, // SleepEx
        { 0xAE626A54FB4B1EFE, 0xC74CD2670540D0E5 }, // ExitProcess
    };
#elif _WIN32
    {
        { 0x1BE725E8, 0x54FE3C56 }, // GetSystemInfo
        { 0x1330050A, 0x472D1883 }, // GetTickCount
        { 0x8A1A09AF, 0x639DAAE1 }, // LoadLibraryA
        { 0x9DC3A7B5, 0x4C5DFFD2 }, // FreeLibrary
        { 0x3E95C861, 0xB86AF953 }, // GetProcAddress
        { 0x2EC158C4, 0xB33593DB }, // VirtualAlloc
        { 0xBFAD008B, 0x086D5CBA }, // VirtualFree
        { 0x684D4B46, 0xFEAE4785 }, // VirtualProtect
        { 0x8066F5F0, 0x1587304E }, // VirtualQuery
        { 0xF3E223E4, 0x58D1C6E8 }, // FlushInstructionCache
        { 0xBFE496D9, 0x144C6CFA }, // SuspendThread
        { 0xA848A36A, 0xF5703D40 }, // ResumeThread
        { 0x0C1FE96C, 0x2E82C6B6 }, // GetThreadContext
        { 0x01C3A55A, 0x543BD02E }, // ExitThread
        { 0x7613A300, 0x2BE798B4 }, // CreateMutexA
        { 0x71D96B6C, 0x44DC831F }, // ReleaseMutex
        { 0x05E6B16C, 0x56C2B5B2 }, // CreateEventA
        { 0xB6BDC3FE, 0x5EA25057 }, // SetEvent
        { 0xCBE31C79, 0xB527BB80 }, // CreateWaitableTimerA
        { 0x174F7821, 0xAF05BDDE }, // SetWaitableTimer
        { 0x8312BDD3, 0xD3DE42B6 }, // WaitForSingleObject
        { 0xCC00FC68, 0xC0A6D2E7 }, // WaitForMultipleObjects
        { 0xC75C037E, 0xA87DF314 }, // DuplicateHandle
        { 0xD4D75A32, 0x585D80CF }, // CloseHandle
        { 0x2361ABF9, 0xBD82334D }, // SetCurrentDirectoryA
        { 0xD69E0B74, 0x2833ECFE }, // SetCurrentDirectoryW
        { 0x2CBDCC0D, 0x2DE6253F }, // SetErrorMode
        { 0x35D0E695, 0x1FAAF404 }, // SleepEx
        { 0xE9D3E889, 0x65A48058 }, // ExitProcess
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        winapi item = list[i];
        void*  proc = SC_FindAPI_MAL(runtime->PML, runtime->hKernel32, item.pHash, item.hKey);
        if (proc == NULL)
        {
            return false;
        }
        list[i].proc = proc;
    }

    runtime->GetSystemInfo          = list[0x00].proc;
    runtime->GetTickCount           = list[0x01].proc;
    runtime->LoadLibraryA           = list[0x02].proc;
    runtime->FreeLibrary            = list[0x03].proc;
    runtime->GetProcAddress         = list[0x04].proc;
    runtime->VirtualAlloc           = list[0x05].proc;
    runtime->VirtualFree            = list[0x06].proc;
    runtime->VirtualProtect         = list[0x07].proc;
    runtime->VirtualQuery           = list[0x08].proc;
    runtime->FlushInstructionCache  = list[0x09].proc;
    runtime->SuspendThread          = list[0x0A].proc;
    runtime->ResumeThread           = list[0x0B].proc;
    runtime->GetThreadContext       = list[0x0C].proc;
    runtime->ExitThread             = list[0x0D].proc;
    runtime->CreateMutexA           = list[0x0E].proc;
    runtime->ReleaseMutex           = list[0x0F].proc;
    runtime->CreateEventA           = list[0x10].proc;
    runtime->SetEvent               = list[0x11].proc;
    runtime->CreateWaitableTimerA   = list[0x12].proc;
    runtime->SetWaitableTimer       = list[0x13].proc;
    runtime->WaitForSingleObject    = list[0x14].proc;
    runtime->WaitForMultipleObjects = list[0x15].proc;
    runtime->DuplicateHandle        = list[0x16].proc;
    runtime->CloseHandle            = list[0x17].proc;
    runtime->SetCurrentDirectoryA   = list[0x18].proc;
    runtime->SetCurrentDirectoryW   = list[0x19].proc;
    runtime->SetErrorMode           = list[0x1A].proc;
    runtime->SleepEx                = list[0x1B].proc;
    runtime->ExitProcess            = list[0x1C].proc;

    // erase data in the large stack
    mem_init(list, sizeof(list));
    return true;
}

static bool initRuntimeEnv(Runtime* runtime)
{
    // get system information
    runtime->GetSystemInfo(&runtime->SysInfo);
    // record initialize tick count
    runtime->InitTick = runtime->GetTickCount();
    // store memory page size
    runtime->PageSize = runtime->SysInfo.PageSize;
    // create global mutex
    HANDLE hMutex = runtime->CreateMutexA(NULL, false, NAME_RT_MUTEX_GLOBAL);
    if (hMutex == NULL)
    {
        return false;
    }
    runtime->hMutex = hMutex;
    return true;
}

#pragma optimize("", off)
static void setMainPagePointer(Runtime* runtime)
{
    *(void**)POINTER_MAIN_PAGE = runtime->MainMemPage;
}
#pragma optimize("", on)

static errno initSubmodules(Runtime* runtime)
{
    // create context data for initialize other modules
    Context context = {
        .ShieldModuleHash    = runtime->Options.ShieldModuleHash,
        .ShieldEntryPoint    = runtime->Options.ShieldEntryPoint,
        .ShieldMemAddress    = runtime->Options.ShieldMemAddress,
        .EnableSecurityMode  = runtime->Options.EnableSecurityMode,
        .DisableDetector     = runtime->Options.DisableDetector,
        .DisableWatchdog     = runtime->Options.DisableWatchdog,
        .DisableSysmon       = runtime->Options.DisableSysmon,
        .NotEraseInstruction = runtime->Options.NotEraseInstruction,
        .NotAdjustProtect    = runtime->Options.NotAdjustProtect,
        .TrackCurrentThread  = runtime->Options.TrackCurrentThread,

        .PEB = runtime->PEB,
        .PML = runtime->PML,
        .MPS = runtime->PageSize,

        .ImageBase = runtime->ImageBase,

        .hKernel32 = runtime->hKernel32,
        .hNtdll    = runtime->hNtdll,

        .GetTickCount           = runtime->GetTickCount,
        .LoadLibraryA           = runtime->LoadLibraryA,
        .FreeLibrary            = runtime->FreeLibrary,
        .GetProcAddress         = runtime->GetProcAddress,
        .VirtualAlloc           = runtime->VirtualAlloc,
        .VirtualFree            = runtime->VirtualFree,
        .VirtualProtect         = runtime->VirtualProtect,
        .VirtualQuery           = runtime->VirtualQuery,
        .SuspendThread          = runtime->SuspendThread,
        .ResumeThread           = runtime->ResumeThread,
        .GetThreadContext       = runtime->GetThreadContext,
        .ExitThread             = runtime->ExitThread,
        .CreateMutexA           = runtime->CreateMutexA,
        .ReleaseMutex           = runtime->ReleaseMutex,
        .CreateEventA           = runtime->CreateEventA,
        .SetEvent               = runtime->SetEvent,
        .CreateWaitableTimerA   = runtime->CreateWaitableTimerA,
        .SetWaitableTimer       = runtime->SetWaitableTimer,
        .WaitForSingleObject    = runtime->WaitForSingleObject,
        .WaitForMultipleObjects = runtime->WaitForMultipleObjects,
        .DuplicateHandle        = runtime->DuplicateHandle,
        .CloseHandle            = runtime->CloseHandle,
        .Sleep                  = GetFuncAddr(&RT_Sleep),

        .MainMemPage = (uintptr)(runtime->MainMemPage),
        .Prologue    = (uintptr)(runtime->Prologue),
        .Epilogue    = (uintptr)(runtime->Epilogue),
        .InstSize    = runtime->InstSize,

        .GetPML = GetFuncAddr(&RT_GetPML),

        .FindAPI_MA = GetFuncAddr(&SC_FindAPI_MA),
        .FindAPI_MH = GetFuncAddr(&SC_FindAPI_MH),

        .malloc  = GetFuncAddr(&RT_malloc),
        .calloc  = GetFuncAddr(&RT_calloc),
        .realloc = GetFuncAddr(&RT_realloc),
        .free    = GetFuncAddr(&RT_free),
        .msize   = GetFuncAddr(&RT_msize),
        .mcap    = GetFuncAddr(&RT_mcap),

        .lock_mods       = GetFuncAddr(&RT_lock_mods),
        .unlock_mods     = GetFuncAddr(&RT_unlock_mods),
        .try_lock_mods   = GetFuncAddr(&RT_try_lock_mods),
        .try_unlock_mods = GetFuncAddr(&RT_try_unlock_mods),

        .add_uptime = GetFuncAddr(&RT_add_uptime),
        .set_health = GetFuncAddr(&RT_set_health),

        .flush_api_cache = GetFuncAddr(&RT_flush_api_cache),

        // for prevent link to internal "memset"
        .ModMutex = { 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    };

    // initialize security submodule
    errno err = initDetector(runtime, &context);
    if (err != NO_ERROR)
    {
        return err;
    }
    if (!runtime->Detector->Detect())
    {
        return ERR_RUNTIME_DETECT_FAILED;
    }
    if (context.EnableSecurityMode)
    {
        DT_Status status;
        runtime->Detector->GetStatus(&status);
        if (status.IsEnabled && status.SafeRank < 60)
        {
            return ERR_RUNTIME_DETECT_UNSAFE_ENV;
        }
    }

    // initialize runtime submodules
    typedef errno (*module_t)(Runtime* runtime, Context* context);
    module_t submodules[] =
    {
        GetFuncAddr(&initLibraryTracker),
        GetFuncAddr(&initMemoryTracker),
        GetFuncAddr(&initThreadTracker),
        GetFuncAddr(&initResourceTracker),
        GetFuncAddr(&initArgumentStore),
        GetFuncAddr(&initInMemoryStorage),
    };
    int seq1[arrlen(submodules)];
    RandSequence(seq1, arrlen(seq1));
    for (int i = 0; i < arrlen(seq1); i++)
    {
        int idx = seq1[i];
        errno errno = submodules[idx](runtime, &context);
        if (errno != NO_ERROR)
        {
            return errno;
        }
    }

    // update context about runtime submodules
    context.mt_malloc  = runtime->MemoryTracker->Alloc;
    context.mt_calloc  = runtime->MemoryTracker->Calloc;
    context.mt_realloc = runtime->MemoryTracker->Realloc;
    context.mt_free    = runtime->MemoryTracker->Free;
    context.mt_msize   = runtime->MemoryTracker->Size;
    context.mt_mcap    = runtime->MemoryTracker->Cap;

    // initialize high-level modules
    module_t hl_modules[] =
    {
        GetFuncAddr(&initWinBase),
        GetFuncAddr(&initWinFile),
        GetFuncAddr(&initWinHTTP),
        GetFuncAddr(&initWinCrypto),
    };
    int seq2[arrlen(hl_modules)];
    RandSequence(seq2, arrlen(seq2));
    for (int i = 0; i < arrlen(seq2); i++)
    {
        int idx = seq2[i];
        errno errno = hl_modules[idx](runtime, &context);
        if (errno != NO_ERROR)
        {
            return errno;
        }
    }

    // update context about continue modules
    context.TT_NewThread        = runtime->ThreadTracker->New;
    context.TT_RecoverThreads   = runtime->ThreadTracker->Recover;
    context.TT_ForceKillThreads = runtime->ThreadTracker->ForceKill;

    context.RT_Cleanup = GetFuncAddr(&RT_Cleanup);
    context.RT_Stop    = GetFuncAddr(&RT_Stop);

    // initialize reliability modules
    err = initWatchdog(runtime, &context);
    if (err != NO_ERROR)
    {
        return err;
    }
    context.WD_IsEnabled = runtime->Watchdog->IsEnabled;

    // update context for sysmon
    context.ModMutex[0] = runtime->Detector->hMutex;
    context.ModMutex[1] = runtime->LibraryTracker->hMutex;
    context.ModMutex[2] = runtime->MemoryTracker->hMutex;
    context.ModMutex[3] = runtime->ThreadTracker->hMutex;
    context.ModMutex[4] = runtime->ResourceTracker->hMutex;
    context.ModMutex[5] = runtime->ArgumentStore->hMutex;
    context.ModMutex[6] = runtime->InMemoryStorage->hMutex;
    context.ModMutex[7] = runtime->Watchdog->hMutex;

    err = initSysmon(runtime, &context);
    if (err != NO_ERROR)
    {
        return err;
    }
    context.ModMutex[8] = runtime->Sysmon->hMutex;

    // copy mutex handle for runtime
    mem_copy(runtime->ModMutexHandle, context.ModMutex, sizeof(context.ModMutex));

    // prepare shield
    err = initShield(runtime, &context);
    if (err != NO_ERROR)
    {
        return err;
    }

    // clean useless API functions in runtime structure
    RandBuffer((byte*)(&runtime->GetSystemInfo), sizeof(uintptr));
    RandBuffer((byte*)(&runtime->CreateMutexA),  sizeof(uintptr));
    return NO_ERROR;
}

static errno initDetector(Runtime* runtime, Context* context)
{
    Detector_M* detector = InitDetector(context);
    if (detector == NULL)
    {
        return GetLastErrno();
    }
    runtime->Detector = detector;
    return NO_ERROR;
}

static errno initLibraryTracker(Runtime* runtime, Context* context)
{
    LibraryTracker_M* tracker = InitLibraryTracker(context);
    if (tracker == NULL)
    {
        return GetLastErrno();
    }
    runtime->LibraryTracker = tracker;
    return NO_ERROR;
}

static errno initMemoryTracker(Runtime* runtime, Context* context)
{
    MemoryTracker_M* tracker = InitMemoryTracker(context);
    if (tracker == NULL)
    {
        return GetLastErrno();
    }
    runtime->MemoryTracker = tracker;
    return NO_ERROR;
}

static errno initThreadTracker(Runtime* runtime, Context* context)
{
    ThreadTracker_M* tracker = InitThreadTracker(context);
    if (tracker == NULL)
    {
        return GetLastErrno();
    }
    runtime->ThreadTracker = tracker;
    return NO_ERROR;
}

static errno initResourceTracker(Runtime* runtime, Context* context)
{
    ResourceTracker_M* tracker = InitResourceTracker(context);
    if (tracker == NULL)
    {
        return GetLastErrno();
    }
    runtime->ResourceTracker = tracker;
    return NO_ERROR;
}

static errno initArgumentStore(Runtime* runtime, Context* context)
{
    ArgumentStore_M* store = InitArgumentStore(context);
    if (store == NULL)
    {
        return GetLastErrno();
    }
    runtime->ArgumentStore = store;
    return NO_ERROR;
}

static errno initInMemoryStorage(Runtime* runtime, Context* context)
{
    InMemoryStorage_M* storage = InitInMemoryStorage(context);
    if (storage == NULL)
    {
        return GetLastErrno();
    }
    runtime->InMemoryStorage = storage;
    return NO_ERROR;
}

static errno initWinBase(Runtime* runtime, Context* context)
{
    WinBase_M* WinBase = InitWinBase(context);
    if (WinBase == NULL)
    {
        return GetLastErrno();
    }
    runtime->WinBase = WinBase;
    return NO_ERROR;
}

static errno initWinFile(Runtime* runtime, Context* context)
{
    WinFile_M* WinFile = InitWinFile(context);
    if (WinFile == NULL)
    {
        return GetLastErrno();
    }
    runtime->WinFile = WinFile;
    return NO_ERROR;
}

static errno initWinHTTP(Runtime* runtime, Context* context)
{
    WinHTTP_M* WinHTTP = InitWinHTTP(context);
    if (WinHTTP == NULL)
    {
        return GetLastErrno();
    }
    runtime->WinHTTP = WinHTTP;
    return NO_ERROR;
}

static errno initWinCrypto(Runtime* runtime, Context* context)
{
    WinCrypto_M* WinCrypto = InitWinCrypto(context);
    if (WinCrypto == NULL)
    {
        return GetLastErrno();
    }
    runtime->WinCrypto = WinCrypto;
    return NO_ERROR;
}

static errno initWatchdog(Runtime* runtime, Context* context)
{
    Watchdog_M* Watchdog = InitWatchdog(context);
    if (Watchdog == NULL)
    {
        return GetLastErrno();
    }
    runtime->Watchdog = Watchdog;
    return NO_ERROR;
}

static errno initSysmon(Runtime* runtime, Context* context)
{
    Sysmon_M* Sysmon = InitSysmon(context);
    if (Sysmon == NULL)
    {
        return GetLastErrno();
    }
    runtime->Sysmon = Sysmon;
    return NO_ERROR;
}

static errno initShield(Runtime* runtime, Context* context)
{
    Shield_M* Shield = InitShield(context);
    if (Shield == NULL)
    {
        return GetLastErrno();
    }
    runtime->Shield = Shield;
    return NO_ERROR;
}

static bool initAPIRedirector(Runtime* runtime)
{
    LibraryTracker_M*  LT = runtime->LibraryTracker;
    MemoryTracker_M*   MT = runtime->MemoryTracker;
    ThreadTracker_M*   TT = runtime->ThreadTracker;
    ResourceTracker_M* RT = runtime->ResourceTracker;

    typedef struct {
        uint pHash; uint hKey; void* api;
    } rdr;

    rdr kernel32[] =
#ifdef _WIN64
    {
        { 0xE6E26FB6E4FE59CE, 0x10BB9100F93D0F8B, GetFuncAddr(&RT_GetProcAddress)       },
        { 0x12A3CA6BA34EAD87, 0x4DC32CDE85E16492, GetFuncAddr(&RT_SetCurrentDirectoryA) },
        { 0x891F575DD3B8F3E6, 0x9D79D93FAB212FD8, GetFuncAddr(&RT_SetCurrentDirectoryW) },
        { 0x5AD097EF20CCF2F6, 0x5D7BAE3110895355, GetFuncAddr(&RT_SetErrorMode)         },
        { 0x0BB33DC44169CD1C, 0x962140866F051973, GetFuncAddr(&RT_SleepHR) /* Sleep */  },
        { 0x0C095075F316AE39, 0x058807734232290F, GetFuncAddr(&RT_SleepEx)              },
        { 0xCA400801FF61A34E, 0xE1AC9F7852E1B05D, LT->LoadLibraryA             },
        { 0xDBD45608DD3235FA, 0xFEC559962D6601D9, LT->LoadLibraryW             },
        { 0xDD32124FBD682FB9, 0x049E6B412B5D442D, LT->LoadLibraryExA           },
        { 0x3FCC5C6C3F82C2BE, 0xAB0B4D9079E2A130, LT->LoadLibraryExW           },
        { 0xB43C2134E4723CA2, 0xF1A7017F9F0C94F3, LT->FreeLibrary              },
        { 0x2788C62E627713D4, 0x866469F01DBF6133, LT->FreeLibraryAndExitThread },
        { 0x66E9F2BA41E2A0C2, 0x1FA76CFBFF379502, MT->VirtualAlloc             },
        { 0x603E56ED7C1537F4, 0x52F1C8C0B584364E, MT->VirtualFree              },
        { 0x3A1198A4675C5EC3, 0x4E8AAF5E5D075B4A, MT->VirtualProtect           },
        { 0xAA7548E17B62D7F8, 0xDCFEB1AF57895416, MT->VirtualQuery             },
        { 0x07DB7553F4BC04BE, 0xF982F021BF11141E, MT->HeapCreate               },
        { 0x8969C9C075773B1F, 0x539B4168D258E6D1, MT->HeapDestroy              },
        { 0x91937D49AF9FFAB9, 0xFF298C980C1FA51C, MT->HeapAlloc                },
        { 0x27D5BFE5E7FEA339, 0xAB8CB329F8568805, MT->HeapReAlloc              },
        { 0xE36248C464C39491, 0x9A21FFFBDCCFCB53, MT->HeapFree                 },
        { 0x9194EEFD9C18C50E, 0x7DDC64814D267471, MT->HeapSize                 },
        { 0x970FBBB0DC7425CC, 0xCCA0C65AC9CA766E, MT->GlobalAlloc              },
        { 0xFF13BFC56EF8D89D, 0xBE039A649C308043, MT->GlobalReAlloc            },
        { 0x992429E01F37C2CB, 0x1DEC53513323DAF3, MT->GlobalFree               },
        { 0x64BDFC1946C13262, 0x0B6B7BAA8E332572, MT->LocalAlloc               },
        { 0xA31D116D5758AC8B, 0xF0B791821E236189, MT->LocalReAlloc             },
        { 0x287C7FAF838267FC, 0x9B059DD440D97436, MT->LocalFree                },
        { 0xB381DBCED8473B71, 0x69E41F98377E69D4, TT->CreateThread             },
        { 0x8B4E255AD410EAD7, 0x9B3C17E907A5484C, TT->ExitThread               },
        { 0xFB3FE4456FDDEE5F, 0x975665E2E638718B, TT->SuspendThread            },
        { 0x9685B1FA1A78AB3B, 0x3147A2CFAB9E8418, TT->ResumeThread             },
        { 0xF4043DBAE6716F9F, 0x292410324C701889, TT->SwitchToThread           },
        { 0x13ABEAA649DA39A3, 0xB13709F7CAE53462, TT->GetThreadContext         },
        { 0xF9200CC7DA05AB20, 0x4916730ED354C174, TT->SetThreadContext         },
        { 0xB92D0C6BFD17BF1B, 0x1D78909BB79BD1D5, TT->TerminateThread          },
        { 0x1478DA3E8F430166, 0xF94DDE91551E2590, TT->TlsAlloc                 },
        { 0x67ED5FAFB746E8A1, 0xEB45D478BCF5D601, TT->TlsFree                  },
        { 0x3530C7A2989E405E, 0x5C88A5AEFEF64834, RT->CreateMutexA             },
        { 0x86944DBCCD5B7259, 0xEEE0821AAFA4CA21, RT->CreateMutexW             },
        { 0x1F96D8316C44D1D4, 0xC7DA7E9547354011, RT->CreateMutexExA           },
        { 0x84F3DC894B35A8DE, 0x0461DDB218E419CE, RT->CreateMutexExW           },
        { 0x35C115CA65D648C4, 0xAA378A25AC9AB5E9, RT->CreateEventA             },
        { 0xEA76EA9AC1F1684A, 0x613B893DE4586476, RT->CreateEventW             },
        { 0xEB18086734568FCC, 0x02B4EE3ADC6A3FCA, RT->CreateEventExA           },
        { 0x181AEEE9288159AF, 0x40C8A0F5488D4F54, RT->CreateEventExW           },
        { 0xA0B7DF1BA221BC91, 0xA2627AA845D4ADD3, RT->CreateSemaphoreA         },
        { 0xE3D01A901CABA296, 0x042F915AFC8193B3, RT->CreateSemaphoreW         },
        { 0x6E639EF7EE6D9176, 0xDB929B6C60E18532, RT->CreateSemaphoreExA       },
        { 0x5166B7C020880A94, 0xF71BCA9C7F743C9D, RT->CreateSemaphoreExW       },
        { 0x70CDEC5C504AE236, 0xB4F98E7A332755BC, RT->CreateWaitableTimerA     },
        { 0xED30A4C7A7A29614, 0xE2DD88A002EB655D, RT->CreateWaitableTimerW     },
        { 0x9AF0CF492273B49C, 0x3944AB9D9A903991, RT->CreateWaitableTimerExA   },
        { 0x6A5ECC6AC89B05A6, 0x9DCD84144BF41E29, RT->CreateWaitableTimerExW   },
        { 0x8CCB1AEF14C033F5, 0xD4471E9865D53D00, RT->CreateFileA              },
        { 0x0354305F3C1449E6, 0xB0226C18509E2B0A, RT->CreateFileW              },
        { 0x90F8CB9DC1CDF040, 0x661D3543C6070977, RT->FindFirstFileA           },
        { 0x9C617D9F679966A9, 0x7C162B0964F1F869, RT->FindFirstFileW           },
        { 0xCAA6B778974CC796, 0xD2B1B4DB48AEB5F4, RT->FindFirstFileExA         },
        { 0xFB3E8E2D3D7BE252, 0x94F2667600F89324, RT->FindFirstFileExW         },
        { 0xE7220B97A4CFC0DF, 0x81EAC7CC69BC5196, RT->CreateIoCompletionPort   },
        { 0xD050B317F8B21AD5, 0xD625D5FF82F41F79, RT->CloseHandle              },
        { 0xCDB1197EBC4CE881, 0x1CA257168FA33339, RT->FindClose                },
    };
#elif _WIN32
    {
        { 0xE7A45E2B, 0x1A710E4F, GetFuncAddr(&RT_GetProcAddress)       },
        { 0x53E41BF6, 0xFFB6599D, GetFuncAddr(&RT_SetCurrentDirectoryA) },
        { 0xCAF08A95, 0xBB8B0575, GetFuncAddr(&RT_SetCurrentDirectoryW) },
        { 0x3DC6B776, 0xD5167779, GetFuncAddr(&RT_SetErrorMode)         },
        { 0x6C9410A5, 0x82568B27, GetFuncAddr(&RT_SleepHR) /* Sleep */  },
        { 0xBA37BAF4, 0x0257F540, GetFuncAddr(&RT_SleepEx)              },
        { 0xBF4F25FA, 0xA131C539, LT->LoadLibraryA             },
        { 0x55A90F7E, 0x5349346C, LT->LoadLibraryW             },
        { 0xD2755464, 0x45CB6974, LT->LoadLibraryExA           },
        { 0xE7E0555F, 0xD02A70FA, LT->LoadLibraryExW           },
        { 0x7CF00FF3, 0x7E640DFE, LT->FreeLibrary              },
        { 0xDD1E6C19, 0x1E78E88B, LT->FreeLibraryAndExitThread },
        { 0x7F957F91, 0x920F498C, MT->VirtualAlloc             },
        { 0xEEB6D179, 0x6BD6BE8F, MT->VirtualFree              },
        { 0x774CBC01, 0x3BEB1DF1, MT->VirtualProtect           },
        { 0x5DBBA619, 0x8A536EBB, MT->VirtualQuery             },
        { 0xFAA011A1, 0xAC5B0514, MT->HeapCreate               },
        { 0x90745C68, 0x7384548D, MT->HeapDestroy              },
        { 0x89B885C0, 0x0CBA79B5, MT->HeapAlloc                },
        { 0x97530A92, 0xEF4E2221, MT->HeapReAlloc              },
        { 0x69AC5529, 0x9F0F87FB, MT->HeapFree                 },
        { 0xA9F4245F, 0xED73D3EF, MT->HeapSize                 },
        { 0xE09ED8B6, 0x012810C6, MT->GlobalAlloc              },
        { 0x424951CC, 0x29D66E25, MT->GlobalReAlloc            },
        { 0xCE2AD6ED, 0x7367D738, MT->GlobalFree               },
        { 0x5827541B, 0x6F8715EE, MT->LocalAlloc               },
        { 0x541A3F04, 0x02FA4395, MT->LocalReAlloc             },
        { 0xEA812AF6, 0x383C2DD3, MT->LocalFree                },
        { 0x521C35F1, 0x5A388498, TT->CreateThread             },
        { 0x827087DB, 0x07E06220, TT->ExitThread               },
        { 0xE64D2B70, 0xA796CEBC, TT->SuspendThread            },
        { 0x7DEAD8EA, 0x1DE3BC77, TT->ResumeThread             },
        { 0x21C2F6AD, 0x4725C481, TT->SwitchToThread           },
        { 0xD306FEA3, 0xC72778A3, TT->GetThreadContext         },
        { 0x7D98D610, 0x82904254, TT->SetThreadContext         },
        { 0x186C157F, 0xCDD4F7E1, TT->TerminateThread          },
        { 0xCEC74DB0, 0x3E447291, TT->TlsAlloc                 },
        { 0xC0C732AD, 0x535505D9, TT->TlsFree                  },
        { 0x43853234, 0x54455751, RT->CreateMutexA             },
        { 0x785F6BF5, 0x3D6CBA5B, RT->CreateMutexW             },
        { 0x21E1899D, 0xAAFF7F26, RT->CreateMutexExA           },
        { 0x87F78CD0, 0x0B1DBA2F, RT->CreateMutexExW           },
        { 0xCC2BAC5F, 0x4D514C21, RT->CreateEventA             },
        { 0x8A86DD59, 0x6A4FA4CF, RT->CreateEventW             },
        { 0xD4311E97, 0xD71810CE, RT->CreateEventExA           },
        { 0xAEE603B7, 0x0DF82E32, RT->CreateEventExW           },
        { 0x623C96BC, 0xF0B6E24D, RT->CreateSemaphoreA         },
        { 0x4C95D8DF, 0x23839135, RT->CreateSemaphoreW         },
        { 0x8ECEED49, 0xB91D8BFA, RT->CreateSemaphoreExA       },
        { 0xB62A71B3, 0x2C269677, RT->CreateSemaphoreExW       },
        { 0x60DA6B28, 0x6AF9FCB6, RT->CreateWaitableTimerA     },
        { 0x36D3924E, 0xF22D3841, RT->CreateWaitableTimerW     },
        { 0x3D1086F9, 0x7ADCB925, RT->CreateWaitableTimerExA   },
        { 0x6FAF9FDA, 0x448DEED2, RT->CreateWaitableTimerExW   },
        { 0x28AF75DA, 0x9DC87AA2, RT->CreateFileA              },
        { 0x02C3BD06, 0x68E258F3, RT->CreateFileW              },
        { 0xDEE66AAD, 0x582829BB, RT->FindFirstFileA           },
        { 0x2CA21077, 0xEB734887, RT->FindFirstFileW           },
        { 0x19EC08BE, 0x236E1ADE, RT->FindFirstFileExA         },
        { 0xCD54D722, 0xB3DD8291, RT->FindFirstFileExW         },
        { 0xA2973DEC, 0x68050AB3, RT->CreateIoCompletionPort   },
        { 0x78265D27, 0x62FF3474, RT->CloseHandle              },
        { 0x56182478, 0xED040027, RT->FindClose                },
    };
#endif
    for (int i = 0; i < arrlen(kernel32); i++)
    {
        rdr   item = kernel32[i];
        void* proc = SC_FindAPI_MA(runtime->hKernel32, item.pHash, item.hKey);
        if (proc == NULL)
        {
            return false;
        }
        runtime->Kernel32RDR[i].src = proc;
        runtime->Kernel32RDR[i].dst = item.api;
    }

    rdr ntdll[] =
#ifdef _WIN64
    {
        { 0x3982604A64E78596, 0xD2E8220B9E91AB06, MT->HeapAlloc   }, // RtlAllocateHeap
        { 0xF739177359998320, 0x94BE3DC57A355EA9, MT->HeapReAlloc }, // RtlReAllocateHeap
        { 0xB989CF296AEDD473, 0x98D91AD0B8459B8F, MT->HeapFree    }, // RtlFreeHeap
        { 0x3D50CA10768C5333, 0xE48E4568E8787962, MT->HeapSize    }, // RtlSizeHeap
        { 0x0F1F3A80639190F0, 0x5DDCB437BC0EB0B5, TT->ExitThread  }, // RtlExitUserThread
    };
#elif _WIN32
    {
        { 0x228ABB50, 0x5B0571BF, MT->HeapAlloc   }, // RtlAllocateHeap
        { 0xFE3F6DB3, 0x5A30B52A, MT->HeapReAlloc }, // RtlReAllocateHeap
        { 0x8C626652, 0x0AB58ABE, MT->HeapFree    }, // RtlFreeHeap
        { 0x8D15D816, 0xCEB11EBF, MT->HeapSize    }, // RtlSizeHeap
        { 0xA1CA7092, 0xF6578A0D, TT->ExitThread  }, // RtlExitUserThread
    };
#endif
    for (int i = 0; i < arrlen(ntdll); i++)
    {
        rdr   item = ntdll[i];
        void* proc = SC_FindAPI_MA(runtime->hNtdll, item.pHash, item.hKey);
        if (proc == NULL)
        {
            return false;
        }
        runtime->NtdllRDR[i].src = proc;
        runtime->NtdllRDR[i].dst = item.api;
    }

    // erase data in the large stack
    mem_init(kernel32, sizeof(kernel32));
    mem_init(ntdll, sizeof(ntdll));
    return true;
}

__declspec(noinline)
static void eraseArgumentStub(Runtime* runtime)
{
    if (runtime->Options.NotEraseInstruction)
    {
        return;
    }
    // stub will be erased, if load argument successfully
    if (!isValidArgumentStub())
    {
        return;
    }
    uintptr stub = (uintptr)(GetFuncAddr(&Argument_Stub));
    uint32  size = calcArgumentStubSize();
    EraseBuffer((byte*)stub, size);
}

__declspec(noinline)
static void eraseRuntimeMethod(Runtime* runtime)
{
    if (runtime->Options.NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&allocateMainMemoryPage));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseRuntimeMethod));
    uintptr size  = end - begin;
    EraseInstruction((void*)begin, size);
}

// ============ next instructions will not be erased after InitRuntime ============

// change memory protect for dynamic update pointer that hard encode.
__declspec(noinline)
static bool adjustPageProtect(Runtime* runtime, DWORD* old)
{
    if (runtime->Options.NotAdjustProtect)
    {
        return true;
    }
    LPVOID addr = runtime->Prologue;
    SIZE_T size = runtime->InstSize;
    return runtime->VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, old);
}

__declspec(noinline)
static bool recoverPageProtect(Runtime* runtime, DWORD protect)
{
    if (runtime->Options.NotAdjustProtect)
    {
        return true;
    }
    LPVOID addr = runtime->Prologue;
    SIZE_T size = runtime->InstSize;
    DWORD old;
    return runtime->VirtualProtect(addr, size, protect, &old);
}

__declspec(noinline)
static errno cleanRuntimeResource(Runtime* runtime, bool init)
{
    errno err = NO_ERROR;
    // close all handles in runtime
    errno enchd = closeHandles(runtime);
    if (enchd != NO_ERROR && err == NO_ERROR)
    {
        err = enchd;
    }
    if (!init)
    {
        return err;
    }
    // must copy variables in Runtime before call EraseBuffer
    VirtualFree_t virtualFree = runtime->VirtualFree;
    void* memPage = runtime->MainMemPage;
    // release main memory page
    EraseBuffer(memPage, MAIN_MEM_PAGE_SIZE);
    if (virtualFree != NULL)
    {
        if (!virtualFree(memPage, 0, MEM_RELEASE) && err == NO_ERROR)
        {
            err = ERR_RUNTIME_CLEAN_FREE_MEM;
        }
    }
    return err;
}

static errno closeHandles(Runtime* runtime)
{
    if (runtime->CloseHandle == NULL)
    {
        return NO_ERROR;
    }
    typedef struct {
        HANDLE handle; errno errno;
    } handle;
    handle list[] =
    {
        { runtime->hMutex, ERR_RUNTIME_CLEAN_H_MUTEX },
    };
    errno errno = NO_ERROR;
    for (int i = 0; i < arrlen(list); i++)
    {
        if (list[i].handle == NULL)
        {
            continue;
        }
        if (!runtime->CloseHandle(list[i].handle) && errno == NO_ERROR)
        {
            errno = list[i].errno;
        }
    }
    return errno;
}

__declspec(noinline)
static void interruptInit(Runtime* runtime)
{
    uint32 oldProtect;
    adjustPageProtect(runtime, &oldProtect);

    // clean submodules if it has been initialized
    if (runtime->Sysmon != NULL)
    {
        runtime->Sysmon->Stop();
    }
    if (runtime->Watchdog != NULL)
    {
        runtime->Watchdog->Stop();
    }

    if (runtime->WinBase != NULL)
    {
        runtime->WinBase->Uninstall();
    }
    if (runtime->WinFile != NULL)
    {
        runtime->WinFile->Uninstall();
    }
    if (runtime->WinHTTP != NULL)
    {
        runtime->WinHTTP->Uninstall();
    }
    if (runtime->WinCrypto != NULL)
    {
        runtime->WinCrypto->Uninstall();
    }

    if (runtime->LibraryTracker != NULL)
    {
        runtime->LibraryTracker->Clean();
    }
    if (runtime->MemoryTracker != NULL)
    {
        runtime->MemoryTracker->Clean();
    }
    if (runtime->ThreadTracker != NULL)
    {
        runtime->ThreadTracker->Clean();
    }
    if (runtime->ResourceTracker != NULL)
    {
        runtime->ResourceTracker->Clean();
    }
    if (runtime->ArgumentStore != NULL)
    {
        runtime->ArgumentStore->Clean();
    }
    if (runtime->InMemoryStorage != NULL)
    {
        runtime->InMemoryStorage->Clean();
    }

    if (runtime->Detector != NULL)
    {
        runtime->Detector->Stop();
    }

    recoverPageProtect(runtime, oldProtect);
}

__declspec(noinline)
static void recoverProcessEnv(Runtime* runtime)
{
    recoverErrorMode(runtime);
}

__declspec(noinline)
static void recoverErrorMode(Runtime* runtime)
{
    if (runtime->ErrorMode == (UINT)(-1))
    {
        return;
    }
    runtime->SetErrorMode(runtime->ErrorMode);
}

// ============================================================================
// cleanInitStack - scrub stack data left behind by runtime initialization
// ============================================================================
//
// Purpose
//   The InitRuntime() initialization chain reads and decrypts a lot of
//   sensitive data, leaving temporary copies on the stack: decrypted
//   Option_Stub data, module handles, API addresses, internal Runtime
//   pointers, hashes, etc. Once those functions return, the data does not
//   disappear by itself; it stays inside the "released" stack frames and can
//   be read by a debugger, a memory scanner, or another thread in the same
//   process. This function pushes a 2048 byte stack frame and zeroes the
//   whole region, wiping out those residual traces.
//
// 
// How it works
//   The x86/x64 stack grows downward. When this function is called, the
//   compiler allocates a 2048 byte local array just below the caller's
//   current stack pointer. That region overlaps the stack space previously
//   used by nested calls (initSubmodules, loadOptionFromStub, each
//   submodule init, initAPIRedirector, etc.). mem_init() zeroes the whole
//   block, so the old frame data is overwritten.
// 
// Coverage and limitations
//   - It covers this function's own frame plus the recently used region
//     below it; local variables of the caller (InitRuntime) at higher
//     addresses are not covered.
//   - It handles the stack only, not the heap (heap data is cleaned by each
//     submodule), and it provides no read protection. It guards against
//     residual data, not against malicious reads.
//   - 2048 is an empirical value chosen from the current maximum nesting
//     depth of the initialization call chain; if deeper initialization
//     calls are added later, this value should be re-evaluated.
//   - After this function returns, the caller must not rely on any local
//     state that lived in this region.
// 
// Division of labor with related erasure mechanisms
//   - eraseArgumentStub()  : erases the argument stub instructions.
//   - eraseRuntimeMethod() : erases the initialization-related method range.
//   - cleanInitStack()     : scrubs residual data from the stack.

#pragma optimize("", off)
__declspec(noinline)
static void cleanInitStack()
{
    byte data[2048];
    mem_init(data, sizeof(data));
}
#pragma optimize("", on)

__declspec(noinline)
static void setRuntimePointer(Runtime* runtime)
{
    *(Runtime**)(POINTER_OFFSET_RUNTIME) = runtime;
}

__declspec(noinline)
static Runtime* getRuntimePointer()
{
    return *(Runtime**)POINTER_OFFSET_RUNTIME;
}

__declspec(noinline)
static bool rt_lock()
{
    Runtime* runtime = getRuntimePointer();

    DWORD event = runtime->WaitForSingleObject(runtime->hMutex, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
static bool rt_unlock()
{
    Runtime* runtime = getRuntimePointer();

    return runtime->ReleaseMutex(runtime->hMutex);
}

__declspec(noinline)
static bool rt_try_lock()
{
    Runtime* runtime = getRuntimePointer();

    DWORD event = runtime->WaitForSingleObject(runtime->hMutex, 1000);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
static void rt_try_unlock()
{
    Runtime* runtime = getRuntimePointer();

    runtime->ReleaseMutex(runtime->hMutex);
}

// +---------+----------+-------------+
// |  size   | capacity | user buffer |
// +---------+----------+-------------+
// |  uint   |   uint   |     var     |
// +---------+----------+-------------+

__declspec(noinline)
void* RT_malloc(uint size)
{
    Runtime* runtime = getRuntimePointer();

    if (size == 0)
    {
        return NULL;
    }
    // ensure the size is a multiple of memory page size.
    // it also for prevent track the special page size.
    SIZE_T pSize = (((size + 16) / runtime->PageSize) + 1) * runtime->PageSize;
    DWORD  type  = MEM_COMMIT|MEM_RESERVE;
    void* addr = runtime->VirtualAlloc(NULL, pSize, type, PAGE_READWRITE);
    if (addr == NULL)
    {
        return NULL;
    }
    // store the size at the head of the memory page
    // ensure the memory address is 16 bytes aligned
    byte* address = (byte*)addr;
    RandBuffer(address, 16);
    // record buffer size
    mem_copy(address, &size, sizeof(size));
    // record buffer capacity
    uint cap = pSize - 16;
    mem_copy(address + sizeof(size), &cap, sizeof(cap));
    dbg_log("[runtime]", "malloc size: %zu", size);
    return (void*)(address + 16);
}

__declspec(noinline)
void* RT_calloc(uint num, uint size)
{
    uint total = num * size;
    if (total == 0)
    {
        return NULL;
    }
    void* addr = RT_malloc(total);
    if (addr == NULL)
    {
        return NULL;
    }
    mem_init(addr, total);
    dbg_log("[runtime]", "calloc num: %zu, size: %zu", num, size);
    return addr;
}

__declspec(noinline)
void* RT_realloc(void* ptr, uint size)
{
    if (ptr == NULL)
    {
        return RT_malloc(size);
    }
    if (size == 0)
    {
        RT_free(ptr);
        return NULL;
    }
    // check need expand capacity
    uint cap = RT_mcap(ptr);
    if (size <= cap)
    {
        *(uint*)((uintptr)(ptr)-16) = size;
        return ptr;
    }
    // allocate new memory
    if (cap < 65536)
    {
        cap = size * 2;
    } else {
        cap = size * 5 / 4; // size *= 1.25
    }
    void* newPtr = RT_malloc(cap);
    if (newPtr == NULL)
    {
        return NULL;
    }
    // copy data to new memory
    uint oldSize = *(uint*)((uintptr)(ptr)-16);
    mem_copy(newPtr, ptr, oldSize);
    // free old memory
    if (!RT_free(ptr))
    {
        RT_free(newPtr);
        return NULL;
    }
    dbg_log("[runtime]", "realloc ptr: 0x%zX, size: %zu", ptr, size);
    return newPtr;
}

__declspec(noinline)
bool RT_free(void* ptr)
{
    Runtime* runtime = getRuntimePointer();

    if (ptr == NULL)
    {
        return true;
    }
    // clean the buffer data before call VirtualFree.
    void* addr = (void*)((uintptr)(ptr)-16);
    uint  size = *(uint*)addr;
    mem_init((byte*)addr, 16+size);
    if (!runtime->VirtualFree(addr, 0, MEM_RELEASE))
    {
        return false;
    }
    dbg_log("[runtime]", "free ptr: 0x%zX", ptr);
    return true;
}

__declspec(noinline)
uint RT_msize(void* ptr)
{
    if (ptr == NULL)
    {
        return 0;
    }
    return *(uint*)((uintptr)(ptr)-16);
}

__declspec(noinline)
uint RT_mcap(void* ptr)
{
    if (ptr == NULL)
    {
        return 0;
    }
    return *(uint*)((uintptr)(ptr)-16+sizeof(uint));
}

__declspec(noinline)
errno RT_lock_mods()
{
    Runtime* runtime = getRuntimePointer();

    typedef bool (*lock_t)();
    typedef struct {
        lock_t lock; errno errno;
    } submodule_t;

    submodule_t list[] =
    {
        { runtime->Sysmon->Lock,          ERR_RUNTIME_LOCK_SYSMON   },
        { runtime->Watchdog->Lock,        ERR_RUNTIME_LOCK_WATCHDOG },
        { runtime->WinHTTP->Lock,         ERR_RUNTIME_LOCK_WIN_HTTP },
        { runtime->LibraryTracker->Lock,  ERR_RUNTIME_LOCK_LIBRARY  },
        { runtime->MemoryTracker->Lock,   ERR_RUNTIME_LOCK_MEMORY   },
        { runtime->ResourceTracker->Lock, ERR_RUNTIME_LOCK_RESOURCE },
        { runtime->ArgumentStore->Lock,   ERR_RUNTIME_LOCK_ARGUMENT },
        { runtime->InMemoryStorage->Lock, ERR_RUNTIME_LOCK_STORAGE  },
        { runtime->Detector->Lock,        ERR_RUNTIME_LOCK_DETECTOR },
        { runtime->ThreadTracker->Lock,   ERR_RUNTIME_LOCK_THREAD   },
    };

    errno errno = NO_ERROR;
    for (int i = 0; i < arrlen(list); i++)
    {
        if (!list[i].lock() && errno == NO_ERROR)
        {
            errno = list[i].errno;
        }
    }
    dbg_lock();

    // erase data in the large stack
    mem_init(list, sizeof(list));
    return errno;
}

__declspec(noinline)
errno RT_unlock_mods()
{
    Runtime* runtime = getRuntimePointer();

    typedef bool (*unlock_t)();
    typedef struct {
        unlock_t unlock; errno errno;
    } submodule_t;

    submodule_t list[] =
    {
        { runtime->ThreadTracker->Unlock,   ERR_RUNTIME_UNLOCK_THREAD   },
        { runtime->Detector->Unlock,        ERR_RUNTIME_UNLOCK_DETECTOR },
        { runtime->LibraryTracker->Unlock,  ERR_RUNTIME_UNLOCK_LIBRARY  },
        { runtime->MemoryTracker->Unlock,   ERR_RUNTIME_UNLOCK_MEMORY   },
        { runtime->ResourceTracker->Unlock, ERR_RUNTIME_UNLOCK_RESOURCE },
        { runtime->ArgumentStore->Unlock,   ERR_RUNTIME_UNLOCK_ARGUMENT },
        { runtime->InMemoryStorage->Unlock, ERR_RUNTIME_UNLOCK_STORAGE  },
        { runtime->WinHTTP->Unlock,         ERR_RUNTIME_UNLOCK_WIN_HTTP },
        { runtime->Watchdog->Unlock,        ERR_RUNTIME_UNLOCK_WATCHDOG },
        { runtime->Sysmon->Unlock,          ERR_RUNTIME_UNLOCK_SYSMON   },
    };

    errno errno = NO_ERROR;
    for (int i = 0; i < arrlen(list); i++)
    {
        if (!list[i].unlock() && errno == NO_ERROR)
        {
            errno = list[i].errno;
        }
    }
    dbg_unlock();

    // erase data in the large stack
    mem_init(list, sizeof(list));
    return errno;
}

__declspec(noinline)
void RT_try_lock_mods()
{
    Runtime* runtime = getRuntimePointer();

    for (int i = 0; i < arrlen(runtime->ModMutexHandle); i++)
    {
        HANDLE hMutex = runtime->ModMutexHandle[i];
        DWORD  event  = runtime->WaitForSingleObject(hMutex, 10000);
        if (event == WAIT_OBJECT_0 || event == WAIT_ABANDONED)
        {
            runtime->ModMutexStatus[i] = true;
        } else {
            runtime->ModMutexStatus[i] = false;
        }
    }
}

__declspec(noinline)
void RT_try_unlock_mods()
{
    Runtime* runtime = getRuntimePointer();

    for (int i = arrlen(runtime->ModMutexHandle) - 1; i >= 0; i--)
    {
        if (runtime->ModMutexStatus[i])
        {
            runtime->ReleaseMutex(runtime->ModMutexHandle[i]);
        }
    }
}

// must use try to lock runtime above these methods about metric,
// because it maybe collide with sysmon when call RT_Stop.

__declspec(noinline)
bool RT_add_uptime(uint32 delta)
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_try_lock())
    {
        return false;
    }

    runtime->RMCore.Uptime += delta;

    rt_try_unlock();
    return true;
}

__declspec(noinline)
bool RT_set_health(bool healthy)
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_try_lock())
    {
        return false;
    }

    runtime->RMCore.IsHealthy = healthy;

    rt_try_unlock();
    return true;
}

__declspec(noinline)
bool RT_flush_api_cache()
{
    Runtime* runtime = getRuntimePointer();

    bool success = false;
    for (;;)
    {
        if (!runtime->MemoryTracker->FlushMu())
        {
            break;
        }
        if (!runtime->ResourceTracker->FlushMu())
        {
            break;
        }
        success = true;
        break;
    }
    return success;
}

__declspec(noinline)
void* SC_FindAPI_MA(void* module, uint procedure, uint key)
{
    return SC_FindAPI_MAL(RT_GetPML(), module, procedure, key);
}

__declspec(noinline)
void* SC_FindAPI_MH(uint module, uint procedure, uint key)
{
    return SC_FindAPI_MHL(RT_GetPML(), module, procedure, key);
}

__declspec(noinline)
void* SC_FindAPI_MAL(PML* pml, void* module, uint procedure, uint key)
{
    void* proc = FindAPI_MAL(pml, module, procedure, key);
    if (proc == NULL)
    {
        return NULL;
    }
    // TODO implement spoof call
    return proc;
}

__declspec(noinline)
void* SC_FindAPI_MHL(PML* pml, uint module, uint procedure, uint key)
{
    void* proc = FindAPI_MHL(pml, module, procedure, key);
    if (proc == NULL)
    {
        return NULL;
    }
    // TODO implement spoof call
    return proc;
}

__declspec(noinline)
SHA256* MW_SHA256New()
{
    Runtime* runtime = getRuntimePointer();

    SHA256* obj = runtime->MemoryTracker->Alloc(sizeof(SHA256));
    // prepare data
    SHA256_Init((SHA256_Ctx*)obj);
    // set method table
    obj->Write = GetFuncAddr(&MW_SHA256_Write);
    obj->Sum   = GetFuncAddr(&MW_SHA256_Sum);
    obj->Reset = GetFuncAddr(&MW_SHA256_Reset);
    obj->Free  = GetFuncAddr(&MW_SHA256_Free);
    return obj;
}

__declspec(noinline)
void MW_SHA256Hash(void* data, uint len, byte (*hash)[32])
{
    SHA256_Ctx ctx;
    SHA256_Init(&ctx);
    SHA256_Write(&ctx, data, len);
    SHA256_Sum(&ctx, hash);
    // erase data in the large stack
    mem_init(&ctx, sizeof(ctx));
}

__declspec(noinline)
void MW_SHA256_Write(SHA256* obj, void* data, uint len)
{
    SHA256_Ctx* ctx = (SHA256_Ctx*)obj;
    SHA256_Write(ctx, data, len);
}

__declspec(noinline)
void MW_SHA256_Sum(SHA256* obj, byte (*hash)[32])
{
    SHA256_Ctx* ctx = (SHA256_Ctx*)obj;
    SHA256_Sum(ctx, hash);
}

__declspec(noinline)
void MW_SHA256_Reset(SHA256* obj)
{
    SHA256_Ctx* ctx = (SHA256_Ctx*)obj;
    SHA256_Init(ctx);
}

__declspec(noinline)
void MW_SHA256_Free(SHA256* obj)
{
    Runtime* runtime = getRuntimePointer();

    runtime->MemoryTracker->Free(obj);
}

__declspec(noinline)
uint MW_Compress(void* dst, void* src, uint len, uint window, uint chain)
{
    Runtime* runtime = getRuntimePointer();

    if (chain == MAXIMUM_CHAIN_LEN)
    {
        return Compress(NULL, dst, src, len, window, chain);
    }
    if (chain == 0)
    {
        chain = DEFAULT_CHAIN_LEN;
    }
    if (chain > MAXIMUM_CHAIN_LEN)
    {
        return (uint)(-1);
    }
    uint size = sizeof(uint16) * HASH_SIZE * chain;
    void* hashTable = runtime->MemoryTracker->Alloc(size);
    uint n = Compress(hashTable, dst, src, len, window, chain);
    runtime->MemoryTracker->Free(hashTable);
    return n;
}

__declspec(noinline)
uint MW_MemScanByValue(void* value, uint size, uintptr* results, uint maxItem)
{
    Runtime* runtime = getRuntimePointer();

    MemScan_Ctx ctx = {
        .MinAddress = (uintptr)(runtime->SysInfo.MinimumApplicationAddress),
        .MaxAddress = (uintptr)(runtime->SysInfo.MaximumApplicationAddress),

        .VirtualQuery = runtime->VirtualQuery,
    };
    return MemScanByValue(&ctx, value, size, results, maxItem);
}

__declspec(noinline)
uint MW_MemScanByConfig(MemScan_Cfg* config, uintptr* results, uint maxItem)
{
    Runtime* runtime = getRuntimePointer();

    MemScan_Ctx ctx = {
        .MinAddress = (uintptr)(runtime->SysInfo.MinimumApplicationAddress),
        .MaxAddress = (uintptr)(runtime->SysInfo.MaximumApplicationAddress),

        .VirtualQuery = runtime->VirtualQuery,
    };
    return MemScanByConfig(&ctx, config, results, maxItem);
}

__declspec(noinline)
void* RT_FindMod_MH(uint module, uint key)
{
    return RT_FindMod_MHL(RT_GetPML(), module, key);
}

__declspec(noinline)
void* RT_FindAPI_MA(void* module, uint procedure, uint key)
{
    return RT_FindAPI_MAL(RT_GetPML(), module, procedure, key);
}

__declspec(noinline)
void* RT_FindAPI_MH(uint module, uint procedure, uint key)
{
    return RT_FindAPI_MHL(RT_GetPML(), module, procedure, key);
}

__declspec(noinline)
void* RT_FindMod_MHL(PML* pml, uint module, uint key)
{
    return FindMod_MHL(pml, module, key);
}

__declspec(noinline)
void* RT_FindAPI_MAL(PML* pml, void* module, uint procedure, uint key)
{
    if (module == NULL)
    {
        SetLastErrno(ERR_RUNTIME_INVALID_HMODULE);
        return NULL;
    }
    // check the module is exists
    if (!IsValidModuleHandle(pml, module))
    {
        SetLastErrno(ERR_RUNTIME_MODULE_NOT_FOUND);
        return NULL;
    }
    // try to find Windows API
    void* proc = SC_FindAPI_MAL(pml, module, procedure, key);
    if (proc == NULL)
    {
        SetLastErrno(ERR_RUNTIME_PROCEDURE_NOT_FOUND);
        return NULL;
    }
    // check api redirector is exists
    void* rdr = getAPIRedirector(proc);
    if (rdr != NULL)
    {
        return rdr;
    }
    return proc;
}

__declspec(noinline)
void* RT_FindAPI_MHL(PML* pml, uint module, uint procedure, uint key)
{
    HMODULE hModule = RT_FindMod_MHL(pml, module, key);
    if (hModule == NULL)
    {
        SetLastErrno(ERR_RUNTIME_INVALID_HMODULE);
        return NULL;
    }
    return RT_FindAPI_MAL(pml, hModule, procedure, key);
}

__declspec(noinline)
void* RT_FindMod_A(byte* module)
{
    return FindMod_A(module);
}

__declspec(noinline)
void* RT_FindMod_W(uint16* module)
{
    return FindMod_W(module);
}

__declspec(noinline)
void* RT_FindAPI_A(byte* module, byte* procedure)
{
    uint key = 0xFFFFFFFF;
    uint mod = CalcModHash_A(module, key);
    HMODULE hModule = FindMod_MHL(RT_GetPML(), mod, key);
    return RT_GetProcAddress(hModule, procedure);
}

__declspec(noinline)
void* RT_FindAPI_W(uint16* module, byte* procedure)
{
    uint key = 0xFFFFFFFF;
    uint mod = CalcModHash_W(module, key);
    HMODULE hModule = FindMod_MHL(RT_GetPML(), mod, key);
    return RT_GetProcAddress(hModule, procedure);
}

__declspec(noinline)
void* RT_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    return RT_GetProcAddressEx(hModule, lpProcName, true);
}

__declspec(noinline)
void* RT_GetProcAddressEx(HMODULE hModule, LPCSTR lpProcName, BOOL redirect)
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return NULL;
    }

    void* proc = RT_GetProcAddressStub(hModule, lpProcName, redirect);

    runtime->RMProc.NumCalls++;

    if (!rt_unlock())
    {
        return NULL;
    }
    return proc;
}

__declspec(noinline)
void* RT_GetProcAddressStub(HMODULE hModule, LPCSTR lpProcName, BOOL redirect)
{
    Runtime* runtime = getRuntimePointer();

    if (hModule == NULL)
    {
        SetLastErrno(ERR_RUNTIME_INVALID_HMODULE);
        return NULL;
    }
    // check is get runtime internal methods
    if (hModule == HMODULE_GLEAM_RT)
    {
        void* method = getRuntimeMethods(lpProcName);
        if (method == NULL)
        {
            SetLastErrno(ERR_RUNTIME_RT_METHOD_NOT_FOUND);
            return NULL;
        }
        runtime->RMProc.NumRTMethod++;
        return method;
    }
    // get process module list snapshot
    PML* pml = RT_GetPML();
    // check the module is exists
    if (!IsValidModuleHandle(pml, hModule))
    {
        SetLastErrno(ERR_RUNTIME_MODULE_NOT_FOUND);
        return NULL;
    }
    // try to get procedure address
    void* proc;
    if (lpProcName <= (LPCSTR)(0xFFFF))
    {
        // process ordinal import
        proc = SC_FindAPI_MAL(pml, hModule, HASHAPI_ORDINAL, (uint)lpProcName);
    } else {
        // generate hash for find Windows API address
        uint hKey  = 0xFFFFFFFF;
        uint pHash = CalcProcHash((byte*)lpProcName, hKey);
        proc = SC_FindAPI_MAL(pml, hModule, pHash, hKey);
    }
    // if not found, use native GetProcAddress and try again
    if (proc == NULL)
    {
        if (lpProcName > (LPCSTR)(0xFFFF))
        {
            dbg_log("[runtime]", "{native} GetProcAddress: 0x%zX, %s", hModule, lpProcName);
        } else {
            uint16 ordinal = (uint16)(uintptr)(lpProcName);
            dbg_log("[runtime]", "{native} GetProcAddress: 0x%zX, %d", hModule, ordinal);
            (void)ordinal; // skip warning C4189
        }
        proc = runtime->GetProcAddress(hModule, lpProcName);
        if (proc == NULL)
        {
            return NULL;
        }
        runtime->RMProc.NumFallback++;
    }
    if (!redirect)
    {
        return proc;
    }
    // check api redirector is exists
    void* rdr = getAPIRedirector(proc);
    if (rdr != NULL)
    {
        runtime->RMProc.NumRedirect++;
        return rdr;
    }
    // if lpProcName is a ordinal, try to get procedure name
    if (lpProcName <= (LPCSTR)(0xFFFF))
    {
        lpProcName = GetProcedureName(pml, hModule, proc);
        if (lpProcName == NULL)
        {
            return proc;
        }
    }
    // check lazy api redirector is exists
    rdr = getLazyAPIRedirector(hModule, lpProcName);
    if (rdr != NULL)
    {
        runtime->RMProc.NumRedirect++;
        return rdr;
    }
    return proc;
}

// disable optimize for use call, NOT jmp to runtime->GetProcAddress.
#pragma optimize("", off)
void* RT_GetProcAddressRaw(HMODULE hModule, LPCSTR lpProcName)
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return NULL;
    }

    void* proc = runtime->GetProcAddress(hModule, lpProcName);

    runtime->RMProc.NumRawProc++;

    if (!rt_unlock())
    {
        return NULL;
    }
    return proc;
}
#pragma optimize("", on)

// getRuntimeMethods is used to obtain runtime internal methods,
// such as GetProcAddress, ExitProcess and submodule methods.
//
// HMODULE hGleamRT = LoadLibraryA("GleamRT.dll");
// ArgGetValue_t AS_GetValue = GetProcAddress(hGleamRT, "AS_GetValue");
static void* getRuntimeMethods(LPCSTR lpProcName)
{
    Runtime* runtime = getRuntimePointer();

    ArgumentStore_M*   AS = runtime->ArgumentStore;
    InMemoryStorage_M* IS = runtime->InMemoryStorage;
    Detector_M*        DT = runtime->Detector;
    Watchdog_M*        WD = runtime->Watchdog;
    Sysmon_M*          SM = runtime->Sysmon;
    Shield_M*          SD = runtime->Shield;

    typedef struct {
        uint pHash; uint hKey; void* method;
    } method;
    method list[] =
#ifdef _WIN64
    {
        { 0x72C26DF267FE1069, 0xD94A0E42AFF3B6CD, GetFuncAddr(&RT_GetProcAddress)    },
        { 0x4F79DF54767444CD, 0xBE758EA0FC623CD6, GetFuncAddr(&RT_GetProcAddressEx)  },
        { 0xC994C51517B5C020, 0x0ABEB36B4EAB5E6C, GetFuncAddr(&RT_GetProcAddressRaw) },
        { 0x0D410397E2792C0E, 0xEF459E62096BA842, GetFuncAddr(&RT_GetTEB)            },
        { 0x89235863FC018896, 0xBCD5BD20A29EB319, GetFuncAddr(&RT_GetPEB)            },
        { 0xA71117B2CCE20660, 0x085CE2B423FB8F83, GetFuncAddr(&RT_GetPML)            },
        { 0xB1FA77826E174621, 0xE8CE6F7431D20C90, GetFuncAddr(&RT_GetOptions)        },
        { 0x618F963CAA5EE348, 0x20EE2A5363818605, GetFuncAddr(&RT_GetRuntimeM)       },
        { 0xA83FF55FECA4B2D5, 0xC9C001C805631D08, GetFuncAddr(&RT_GetInfo)           },
        { 0x3F0F1951378BA2D7, 0x3990B978D311CE13, GetFuncAddr(&RT_GetMetrics)        },
        { 0xF1B02539240FCCBE, 0x7CDDB06DD3B3380B, GetFuncAddr(&RT_SleepHR)           },
        { 0xC202636AB59E272A, 0x83FABCD3C9ED5B2E, GetFuncAddr(&RT_Sleep)             },
        { 0x7D7CFE6E023217B8, 0x51D583187BB49302, GetFuncAddr(&RT_ExitProcess)       },
        { 0x479C7B50DBFADEE7, 0x649073A187F0F0A9, AS->GetValue   }, // AS_GetValue
        { 0x41D042835BA4C499, 0xD74A73D3EE16AE15, AS->GetPointer }, // AS_GetPointer
        { 0xE84B8AF19E5545A2, 0xCE033EAF91F7C68A, AS->Erase      }, // AS_Erase
        { 0xD0E223D64B8DCDD0, 0x1CF6D4FF24ED869B, AS->EraseAll   }, // AS_EraseAll
        { 0xEF091353A54C024F, 0x06A86B2D442F36C4, AS->GetStatus  }, // AS_GetStatus
        { 0xC6CB35CD39A67EAC, 0x015D074AF57976A1, IS->SetValue   }, // IS_SetValue
        { 0x6337FA1ECA8843D2, 0x36206F50F948F913, IS->GetValue   }, // IS_GetValue
        { 0x773674E47B0053B8, 0x0A681F5428C13912, IS->GetPointer }, // IS_GetPointer
        { 0x0B5E3CDD9E8D1718, 0x96E689FB7E624071, IS->Delete     }, // IS_Delete
        { 0x20EF072CE85923F8, 0x0A63186150433F11, IS->DeleteAll  }, // IS_DeleteAll
        { 0x1E1856EDCFDDA5E4, 0xCD66F699F3FF7867, IS->GetStatus  }, // IS_GetStatus
        { 0x581F53A28A65268E, 0xED463BBEAA5FD89F, DT->Detect     }, // DT_Detect
        { 0xFB549442A42025E2, 0x2B8AB0BD179B4250, DT->GetStatus  }, // DT_GetStatus
        { 0xD08874D760CA7D86, 0xA4719EDF574FF3BD, WD->SetHandler }, // WD_SetHandler
        { 0x43F0DB91ACB312F1, 0x6188D3AFB7FF35FD, WD->SetTimeout }, // WD_SetTimeout
        { 0xC452D582688E6748, 0x306E7BA258D6F057, WD->Kick       }, // WD_Kick
        { 0x6466D654DC42A2F5, 0xDDF182373074C274, WD->Enable     }, // WD_Enable
        { 0x93B95D821AC7FDBB, 0x292E300258544350, WD->Disable    }, // WD_Disable
        { 0xA203A663F5364056, 0xDE186C4522AF6A07, WD->IsEnabled  }, // WD_IsEnabled
        { 0xA86FDE488282A161, 0x841E942B8732594B, WD->GetStatus  }, // WD_GetStatus
        { 0x08BE5269AFFBD475, 0x1B42FB830E389DC3, SM->GetStatus  }, // SM_GetStatus
        { 0x1EF56550F2022EED, 0x39604BE4E97C1DA8, SD->GetStatus  }, // SD_GetStatus
    };
#elif _WIN32
    {
        { 0xF8A848AD, 0x6533FEA7, GetFuncAddr(&RT_GetProcAddress)    },
        { 0x4292920A, 0x45AFC98F, GetFuncAddr(&RT_GetProcAddressEx)  },
        { 0x52FC5757, 0x5737AAE4, GetFuncAddr(&RT_GetProcAddressRaw) },
        { 0xB5B44B90, 0xB7C4AFC0, GetFuncAddr(&RT_GetTEB)            },
        { 0xB6DA1A98, 0x48E18193, GetFuncAddr(&RT_GetPEB)            },
        { 0x0353F556, 0x8A5CF1BA, GetFuncAddr(&RT_GetPML)            },
        { 0xD4D119FF, 0x8CD7C9D0, GetFuncAddr(&RT_GetOptions)        },
        { 0x2414448A, 0x2E37B5DF, GetFuncAddr(&RT_GetRuntimeM)       },
        { 0x41205F31, 0x2E96AC51, GetFuncAddr(&RT_GetInfo)           },
        { 0xD731BCE7, 0x1E7A2A1A, GetFuncAddr(&RT_GetMetrics)        },
        { 0xC38FBBF5, 0xDEED529C, GetFuncAddr(&RT_SleepHR)           },
        { 0x707547CF, 0x66DCFA17, GetFuncAddr(&RT_Sleep)             },
        { 0xC661D6AC, 0x844DD401, GetFuncAddr(&RT_ExitProcess)       },
        { 0x6DD5CD24, 0xF0B9A21D, AS->GetValue   }, // AS_GetValue
        { 0xB8A08D9B, 0x7DB3ECC2, AS->GetPointer }, // AS_GetPointer
        { 0x18EF1CF3, 0x978EAC96, AS->Erase      }, // AS_Erase
        { 0xF3F8E721, 0xB6B8CE66, AS->EraseAll   }, // AS_EraseAll
        { 0xE5718EF2, 0x3A32578F, AS->GetStatus  }, // AS_GetStatus
        { 0x059C9C41, 0x580504E7, IS->SetValue   }, // IS_SetValue
        { 0xCC98B76B, 0x607C67D7, IS->GetValue   }, // IS_GetValue
        { 0x8D311A4E, 0xDCEBC05E, IS->GetPointer }, // IS_GetPointer
        { 0xC0182D65, 0x9990E05B, IS->Delete     }, // IS_Delete
        { 0x985542B3, 0x41D8CA6A, IS->DeleteAll  }, // IS_DeleteAll
        { 0x5807F4F2, 0xFBF697C8, IS->GetStatus  }, // IS_GetStatus
        { 0xC1D58FC0, 0xB24370DA, DT->Detect     }, // DT_Detect
        { 0x501A173A, 0x871A6960, DT->GetStatus  }, // DT_GetStatus
        { 0x7F44D8EC, 0x5B3C26E3, WD->SetHandler }, // WD_SetHandler
        { 0x5BEBCA2A, 0xF523475E, WD->SetTimeout }, // WD_SetTimeout
        { 0x22071C46, 0x98C6F05B, WD->Kick       }, // WD_Kick
        { 0xD43187BC, 0x6247B19C, WD->Enable     }, // WD_Enable
        { 0x2BFE9370, 0x0E5A84B4, WD->Disable    }, // WD_Disable
        { 0x219D299A, 0xBFCD277B, WD->IsEnabled  }, // WD_IsEnabled
        { 0x5210B9A0, 0xB6838D89, WD->GetStatus  }, // WD_GetStatus
        { 0xB59E4AC9, 0x7BDB4375, SM->GetStatus  }, // SM_GetStatus
        { 0x728F99BA, 0xEEB2905C, SD->GetStatus  }, // SD_GetStatus
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        method item = list[i];
        if (CalcProcHash((byte*)lpProcName, item.hKey) != item.pHash)
        {
            continue;
        }
        // erase data in the large stack
        mem_init(list, sizeof(list));
        return item.method;
    }
    // erase data in the large stack
    mem_init(list, sizeof(list));
    return NULL;
}

static void* getAPIRedirector(void* proc)
{
    Runtime* runtime = getRuntimePointer();

    for (int i = 0; i < arrlen(runtime->Kernel32RDR); i++)
    {
        API_RDR rdr = runtime->Kernel32RDR[i];
        if (rdr.src != proc)
        {
            continue;
        }
        return rdr.dst;
    }
    for (int i = 0; i < arrlen(runtime->NtdllRDR); i++)
    {
        API_RDR rdr = runtime->NtdllRDR[i];
        if (rdr.src != proc)
        {
            continue;
        }
        return rdr.dst;
    }
    return NULL;
}

// getLazyAPIRedirector is used to FindAPI after call LoadLibrary.
// Redirectors in initAPIRedirector() are all in kernel32.dll.
static void* getLazyAPIRedirector(HMODULE hModule, LPCSTR lpProcName)
{
    Runtime* runtime = getRuntimePointer();

    MemoryTracker_M*   MT = runtime->MemoryTracker;
    ResourceTracker_M* RT = runtime->ResourceTracker;

    // get dll base name for calculate module hash
    WCHAR dllName[MAX_PATH];
    mem_init(dllName, sizeof(dllName));
    if (GetModuleBaseName(RT_GetPML(), hModule, dllName, MAX_PATH) == 0)
    {
        return NULL;
    }

    typedef struct {
        uint mHash; uint pHash; uint hKey; void* api;
    } rdr;
    rdr list[] =
#ifdef _WIN64
    {
        { 0x5254CA58A04C6861, 0x13B5CA12DD915BFF, 0x90E47B3ACA936DDF, MT->msvcrt_malloc    },
        { 0x4F5F3C8E02424715, 0x2DE690AE65E7CA95, 0xF19FC35BA1098695, MT->msvcrt_calloc    },
        { 0xAFB8889578B00466, 0xA8B9D01521BE59A8, 0x56797427ADC736F5, MT->msvcrt_realloc   },
        { 0xE7C6D3E8F64212DB, 0xDCE3F452DF107F71, 0xB8A2CB36A709EF6F, MT->msvcrt_free      },
        { 0xC1E9BA292B4AE7A4, 0x0C064C9575BCF15B, 0xC4999748966A9858, MT->msvcrt_msize     },
        { 0xAA909AD9DB1B157E, 0xA5E606AF657B5E09, 0x5546D5EF6EBD88F4, MT->ucrtbase_malloc  },
        { 0xE45A40568AD159B2, 0xDFAFAC2C1531A19D, 0xB25BA66565A7746C, MT->ucrtbase_calloc  },
        { 0x79F4536182B35D04, 0x6FDB742B0500FBE3, 0x23CA792DFEE7E60B, MT->ucrtbase_realloc },
        { 0xAED68A03A785FA47, 0xD5B8EA4569EA5C32, 0xDED2EB337D9116BC, MT->ucrtbase_free    },
        { 0x03497789B54E7CA9, 0xFF4EE05FAFBAC456, 0x567A7168C11256EE, MT->ucrtbase_msize   },
        { 0x625DD62ED359C958, 0x3091FBE2377A1176, 0x22A27DECEAF2266F, RT->RegCreateKeyA    },
        { 0x7B698BFB22192AA3, 0xEA50E9DC003C8EA2, 0x950CD32D7E2121B8, RT->RegCreateKeyW    },
        { 0x41F5B7D40FB03A4B, 0xC708FE55618EAE52, 0x51D5149B4857934B, RT->RegCreateKeyExA  },
        { 0xB4C76DDCB73696B4, 0xA7A86DB8B2DD33B9, 0x98E110EE82D21BDD, RT->RegCreateKeyExW  },
        { 0x36051AE7E56AAECE, 0x321942AA68DD9653, 0x0F536179870DF295, RT->RegOpenKeyA      },
        { 0x3385B5A869495B06, 0x5805A4074843E065, 0xD47A4EC8E0FF8E99, RT->RegOpenKeyW      },
        { 0x6EA9DF91C3CDCE6B, 0xA212700247963F1E, 0xF7B9272CA7F2B111, RT->RegOpenKeyExA    },
        { 0x7E7F92C8D608D302, 0xC3AFBAD56325AAF8, 0x2FF2F4B325AB0D60, RT->RegOpenKeyExW    },
        { 0xD178185E7C76C08B, 0x4374BF609B14CECE, 0x847060A18FB337BC, RT->RegCloseKey      },
        { 0x43915A5C5D2EEFAD, 0x2C190CCAB8AF60EE, 0xC5BEBEF2DB5B6ADB, RT->WSAStartup       },
        { 0x9E03289691D1AC6D, 0x64663633D27E11B2, 0x70ACEA9F645A4CAD, RT->WSACleanup       },
        { 0x10BE0476CCD0949A, 0x65AB8A1BB8C93451, 0x5094B7750A4EEF9D, RT->WSASocketA       },
        { 0x991A160A43356D61, 0x4A5AD3FA8260D517, 0xE9AC8B5A6007860D, RT->WSASocketW       },
        { 0x6D3AE16372B1A0DB, 0x0F9CD5C024047F6F, 0xAAC7634A7F85F581, RT->WSAIoctl         },
        { 0x7736E0C240C9B448, 0xE69F48EBE315D71D, 0x71CF1A836E0A477C, RT->socket           },
        { 0x5BAFA015C25A8294, 0xF9276424913FC0E2, 0xC2D98F6758BE8E93, RT->accept           },
        { 0x4317E765A5C19858, 0x8AF7DA94AE27ADFB, 0xC9BE98972D22AFA7, RT->shutdown         },
        { 0x0F5B6F87DA763249, 0x8C1307AA01358E71, 0xC24A6EE00FDC1A9E, RT->closesocket      },
    };
#elif _WIN32
    {
        { 0x779E8E68, 0xC28F9C78, 0x742FAD69, MT->msvcrt_malloc    },
        { 0xF72036C1, 0xA187A89D, 0x0A468719, MT->msvcrt_calloc    },
        { 0x51F6F0AF, 0xD8427F9B, 0x161B5A2A, MT->msvcrt_realloc   },
        { 0xC0AE317A, 0xB2CBF2E1, 0x3A6F2FEF, MT->msvcrt_free      },
        { 0x470C76A8, 0x985FAB1A, 0x6A95FAA9, MT->msvcrt_msize     },
        { 0xBF0F01E4, 0x840E093C, 0xA7A90445, MT->ucrtbase_malloc  },
        { 0xB00F91E3, 0xAD87A573, 0x8B4E88EB, MT->ucrtbase_calloc  },
        { 0xCD03B519, 0xF4D21253, 0x51493B49, MT->ucrtbase_realloc },
        { 0x493A8A6C, 0xA862B408, 0x24314545, MT->ucrtbase_free    },
        { 0x2017A8CC, 0xD163E2C6, 0xFCB661CE, MT->ucrtbase_msize   },
        { 0x22355E5D, 0xE1A90917, 0xADE97876, RT->RegCreateKeyA    },
        { 0x07F34B77, 0xC766F647, 0x45557C5C, RT->RegCreateKeyW    },
        { 0x5E5746DB, 0xCA92BD13, 0xA3360B59, RT->RegCreateKeyExA  },
        { 0x83D55FB4, 0x98C92D4A, 0x69B59766, RT->RegCreateKeyExW  },
        { 0x6A9426C0, 0x53C33F65, 0x13ECFAA3, RT->RegOpenKeyA      },
        { 0x63DE6FAA, 0x1A6BBB07, 0x033261DF, RT->RegOpenKeyW      },
        { 0xF3B62990, 0x95170248, 0x181E2275, RT->RegOpenKeyExA    },
        { 0x84BCAAAF, 0x261D837D, 0xFA0FFFDA, RT->RegOpenKeyExW    },
        { 0x18E3E426, 0x901A72E3, 0x24A3A166, RT->RegCloseKey      },
        { 0x131590EA, 0x18C9638C, 0x60893AC1, RT->WSAStartup       },
        { 0xB3174609, 0x28E27407, 0xE9139041, RT->WSACleanup       },
        { 0x0B305DC1, 0xD03A3A72, 0x4AE762DC, RT->WSASocketA       },
        { 0x4A6DD610, 0x13DB0032, 0xF7657ED7, RT->WSASocketW       },
        { 0xE4A294EC, 0x86DBB084, 0x151427B4, RT->WSAIoctl         },
        { 0xB23F6E3E, 0xAF3DA115, 0xC156AB6D, RT->socket           },
        { 0x31ABD834, 0xDE2BAF2B, 0x19EB6D1E, RT->accept           },
        { 0x9BAB4EBA, 0x494E2BD1, 0x101223CE, RT->shutdown         },
        { 0x209A93DA, 0x6008F821, 0x6A713103, RT->closesocket      },
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        rdr item = list[i];
        if (CalcModHash_W(dllName, item.hKey) != item.mHash)
        {
            continue;
        }
        if (CalcProcHash((byte*)lpProcName, item.hKey) != item.pHash)
        {
            continue;
        }
        // erase data in the large stack
        mem_init(list, sizeof(list));
        mem_init(dllName, sizeof(dllName));
        return item.api;
    }
    // erase data in the large stack
    mem_init(list, sizeof(list));
    mem_init(dllName, sizeof(dllName));
    return NULL;
}

__declspec(noinline)
TEB* RT_GetTEB()
{
#ifdef _WIN64
    TEB* teb = (TEB*)__readgsqword(0x30);
#elif _WIN32
    TEB* teb = (TEB*)__readfsdword(0x18);
#endif
    return teb;
}

__declspec(noinline)
PEB* RT_GetPEB()
{
    Runtime* runtime = getRuntimePointer();

    return runtime->PEB;
}

__declspec(noinline)
PML* RT_GetPML()
{
    Runtime* runtime = getRuntimePointer();

    return runtime->PML;
}

__declspec(noinline)
HMODULE RT_GetMainEXE()
{
    Runtime* runtime = getRuntimePointer();

    return runtime->ImageBase;
}

__declspec(noinline)
HMODULE RT_GetKernel32()
{
    Runtime* runtime = getRuntimePointer();

    return runtime->hKernel32;
}

__declspec(noinline)
HMODULE RT_GetNtdll()
{
    Runtime* runtime = getRuntimePointer();

    return runtime->hNtdll;
}

__declspec(noinline)
BOOL RT_SetCurrentDirectoryA(LPSTR lpPathName)
{
    Runtime* runtime = getRuntimePointer();

    dbg_log("[runtime]", "SetCurrentDirectoryA: %s", lpPathName);

    // for call SetLastError
    if (lpPathName == NULL)
    {
        return runtime->SetCurrentDirectoryA(lpPathName);
    }
    // prevent the upper module change the
    // current directory in the host process
    if (*lpPathName != '*')
    {
        return true;
    }
    return runtime->SetCurrentDirectoryA(++lpPathName);
}

__declspec(noinline)
BOOL RT_SetCurrentDirectoryW(LPWSTR lpPathName)
{
    Runtime* runtime = getRuntimePointer();

    dbg_log("[runtime]", "SetCurrentDirectoryW: %ls", lpPathName);

    // for call SetLastError
    if (lpPathName == NULL)
    {
        return runtime->SetCurrentDirectoryW(lpPathName);
    }
    // prevent the upper module change the
    // current directory in the host process
    if (*lpPathName != L'*')
    {
        return true;
    }
    return runtime->SetCurrentDirectoryW(++lpPathName);
}

__declspec(noinline)
UINT RT_SetErrorMode(UINT uMode)
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return 0;
    }

    UINT mode = runtime->SetErrorMode(uMode);

    // only record the first time
    if (runtime->ErrorMode == (UINT)(-1))
    {
        runtime->ErrorMode = mode;
    }

    if (!rt_unlock())
    {
        return 0;
    }
    return mode;
}

__declspec(noinline)
void RT_Sleep(DWORD dwMilliseconds)
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return;
    }

    ThdSleep_t Sleep = runtime->ThreadTracker->Sleep;

    if (!rt_unlock())
    {
        return;
    }
    Sleep(dwMilliseconds);
}

__declspec(noinline)
DWORD RT_SleepEx(DWORD dwMilliseconds, BOOL bAlertable)
{
    if (!bAlertable)
    {
        RT_SleepHR(dwMilliseconds);
        return 0;
    }

    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return 0;
    }

    SleepEx_t sleepEx = runtime->SleepEx;

    if (!rt_unlock())
    {
        return 0;
    }
    return sleepEx(dwMilliseconds, bAlertable);
}

__declspec(noinline)
void RT_ExitProcess(UINT uExitCode)
{
    Runtime* runtime = getRuntimePointer();

    RT_Cleanup();
    runtime->Shield->Clean();

    runtime->ExitProcess(uExitCode);
}

__declspec(noinline)
errno RT_SleepHR(DWORD dwMilliseconds)
{
    Runtime* runtime = getRuntimePointer();

    // if sleep duration is too small, call the simulation
    // of the kernel32.Sleep
    // because some developer may be use the short sleep
    // for implement the thread synchronization
    if (dwMilliseconds < 100)
    {
        RT_Sleep(dwMilliseconds);
        return NO_ERROR;
    }

    // make sure the sleep time is a multiple of 1s
    dwMilliseconds = (dwMilliseconds / 1000) * 1000;
    if (dwMilliseconds == 0)
    {
        dwMilliseconds = 1000;
    }
    // for check the performance about hide and recover
#ifdef ENABLE_FAST_SLEEP
    dwMilliseconds = 1;
#endif

    if (!rt_lock())
    {
        return ERR_RUNTIME_LOCK;
    }
    errno errlm = RT_lock_mods();
    if (errlm != NO_ERROR)
    {
        return errlm;
    }

    // must update this metric field first for
    // calculate the sleep average elapsed time
    runtime->RMSleep.NumCalls++;

    errno error = NO_ERROR;
    for (;;)
    {
        DWORD tick = runtime->GetTickCount();
        errno err  = hide(runtime);
        if (err != NO_ERROR && error == NO_ERROR)
        {
            error = err;
        }
        DWORD delta = runtime->GetTickCount() - tick + 1;
        addPreSleepElapsed(delta);

        err = sleep(runtime, dwMilliseconds);
        if (err != NO_ERROR && error == NO_ERROR)
        {
            error = err;
        }

        tick = runtime->GetTickCount();
        err = recover(runtime);
        if (err != NO_ERROR && error == NO_ERROR)
        {
            error = err;
        }
        delta = runtime->GetTickCount() - tick + 1;
        addPostSleepElapsed(delta);
        break;
    }

    // detect environment after each sleep
    runtime->Detector->Detect();

    errno errum = RT_unlock_mods();
    if (errum != NO_ERROR)
    {
        return errum;
    }
    if (!rt_unlock())
    {
        return ERR_RUNTIME_UNLOCK;
    }
    return error;
}

__declspec(noinline)
static errno hide(Runtime* runtime)
{
    typedef errno (*submodule_t)();
    submodule_t mods[] = {
        runtime->ThreadTracker->Suspend,

        runtime->Sysmon->Pause,
        runtime->Watchdog->Pause,

        runtime->WinHTTP->Clean,
        runtime->WinCrypto->Clean,

        runtime->LibraryTracker->Encrypt,
        runtime->MemoryTracker->Encrypt,
        runtime->ResourceTracker->Encrypt,
        runtime->ArgumentStore->Encrypt,
        runtime->InMemoryStorage->Encrypt,
    };
    errno err = NO_ERROR;
    for (int i = 0; i < arrlen(mods); i++)
    {
        errno enmod = mods[i]();
        if (enmod != NO_ERROR && !CAN_IGNORE_ERR(enmod) && err == NO_ERROR)
        {
            err = enmod;
        }
    }
    // erase data in the large stack
    mem_init(mods, sizeof(mods));
    return err;
}

__declspec(noinline)
static errno recover(Runtime* runtime)
{
    typedef errno (*submodule_t)();
    submodule_t mods[] = {
        runtime->InMemoryStorage->Decrypt,
        runtime->ArgumentStore->Decrypt,
        runtime->ResourceTracker->Decrypt,
        runtime->MemoryTracker->Decrypt,
        runtime->LibraryTracker->Decrypt,

        runtime->Watchdog->Continue,
        runtime->Sysmon->Continue,

        runtime->ThreadTracker->Resume,
    };
    errno err = NO_ERROR;
    for (int i = 0; i < arrlen(mods); i++)
    {
        errno enmod = mods[i]();
        if (enmod != NO_ERROR && !CAN_IGNORE_ERR(enmod) && err == NO_ERROR)
        {
            err = enmod;
        }
    }
    // erase data in the large stack
    mem_init(mods, sizeof(mods));
    return err;
}

__declspec(noinline)
static errno sleep(Runtime* runtime, uint32 milliseconds)
{
    errno errno = runtime->Shield->Sleep(milliseconds);
    if (errno != NO_ERROR)
    {
        return errno;
    }
    return NO_ERROR;
}

__declspec(noinline)
static void addPreSleepElapsed(int32 milliseconds)
{
    Runtime* runtime = getRuntimePointer();

    RT_SleepM* sleep = &runtime->RMSleep;

    sleep->LastPreElapsed   = milliseconds;
    sleep->TotalPreElapsed += milliseconds;

    if (sleep->MinPreElapsed == 0)
    {
        sleep->MinPreElapsed = milliseconds;
    }
    if (milliseconds < sleep->MinPreElapsed)
    {
        sleep->MinPreElapsed = milliseconds;
    }
    if (milliseconds > sleep->MaxPreElapsed)
    {
        sleep->MaxPreElapsed = milliseconds;
    }
    sleep->AvgPreElapsed = (int32)(sleep->TotalPreElapsed / sleep->NumCalls);
}

__declspec(noinline)
static void addPostSleepElapsed(int32 milliseconds)
{
    Runtime* runtime = getRuntimePointer();

    RT_SleepM* sleep = &runtime->RMSleep;

    sleep->LastPostElapsed   = milliseconds;
    sleep->TotalPostElapsed += milliseconds;

    if (sleep->MinPostElapsed == 0)
    {
        sleep->MinPostElapsed = milliseconds;
    }
    if (milliseconds < sleep->MinPostElapsed)
    {
        sleep->MinPostElapsed = milliseconds;
    }
    if (milliseconds > sleep->MaxPostElapsed)
    {
        sleep->MaxPostElapsed = milliseconds;
    }
    sleep->AvgPostElapsed = (int32)(sleep->TotalPostElapsed / sleep->NumCalls);
}

__declspec(noinline)
errno RT_Hide()
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return ERR_RUNTIME_LOCK;
    }
    errno errlm = RT_lock_mods();
    if (errlm != NO_ERROR)
    {
        return errlm;
    }

    errno err = hide(runtime);

    errno errum = RT_unlock_mods();
    if (errum != NO_ERROR)
    {
        return errum;
    }
    if (!rt_unlock())
    {
        return ERR_RUNTIME_UNLOCK;
    }
    return err;
}

__declspec(noinline)
errno RT_Recover()
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return ERR_RUNTIME_LOCK;
    }
    errno errlm = RT_lock_mods();
    if (errlm != NO_ERROR)
    {
        return errlm;
    }

    errno err = recover(runtime);

    errno errum = RT_unlock_mods();
    if (errum != NO_ERROR)
    {
        return errum;
    }
    if (!rt_unlock())
    {
        return ERR_RUNTIME_UNLOCK;
    }
    return err;
}

__declspec(noinline)
errno RT_GetOptions(Runtime_Opts* opts)
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return ERR_RUNTIME_LOCK;
    }

    // MUST use mem_copy for prevent link to memcpy
    mem_copy(opts, &runtime->Options, sizeof(Runtime_Opts));

    if (!rt_unlock())
    {
        return ERR_RUNTIME_UNLOCK;
    }
    return NO_ERROR;
}

__declspec(noinline)
errno RT_GetRuntimeM(Runtime_M* rtm)
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return ERR_RUNTIME_LOCK;
    }

    // MUST use mem_copy for prevent link to the memcpy
    // "*rtm = *runtime->RuntimeM;" will failed to compile
    mem_copy(rtm, runtime->RuntimeM, sizeof(Runtime_M));

    if (!rt_unlock())
    {
        return ERR_RUNTIME_UNLOCK;
    }
    return NO_ERROR;
}

__declspec(noinline)
errno RT_GetInfo(Runtime_Info* info)
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return ERR_RUNTIME_LOCK;
    }

    // MUST use mem_copy for prevent link to memcpy
    mem_copy(info, &runtime->Info, sizeof(Runtime_Info));

    if (!rt_unlock())
    {
        return ERR_RUNTIME_UNLOCK;
    }
    return NO_ERROR;
}

__declspec(noinline)
errno RT_GetMetrics(Runtime_Metrics* metrics)
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return ERR_RUNTIME_LOCK;
    }

    errno errno = NO_ERROR;
    if (!runtime->LibraryTracker->GetStatus(&metrics->Library))
    {
        errno = ERR_RUNTIME_GET_STATUS_LIBRARY;
    }
    if (!runtime->MemoryTracker->GetStatus(&metrics->Memory))
    {
        errno = ERR_RUNTIME_GET_STATUS_MEMORY;
    }
    if (!runtime->ThreadTracker->GetStatus(&metrics->Thread))
    {
        errno = ERR_RUNTIME_GET_STATUS_THREAD;
    }
    if (!runtime->ResourceTracker->GetStatus(&metrics->Resource))
    {
        errno = ERR_RUNTIME_GET_STATUS_RESOURCE;
    }
    if (!runtime->ArgumentStore->GetStatus(&metrics->Argument))
    {
        errno = ERR_RUNTIME_GET_STATUS_ARGUMENT;
    }
    if (!runtime->InMemoryStorage->GetStatus(&metrics->Storage))
    {
        errno = ERR_RUNTIME_GET_STATUS_STORAGE;
    }
    if (!runtime->Detector->GetStatus(&metrics->Detector))
    {
        errno = ERR_RUNTIME_GET_STATUS_DETECTOR;
    }
    if (!runtime->Watchdog->GetStatus(&metrics->Watchdog))
    {
        errno = ERR_RUNTIME_GET_STATUS_WATCHDOG;
    }
    if (!runtime->Sysmon->GetStatus(&metrics->Sysmon))
    {
        errno = ERR_RUNTIME_GET_STATUS_SYSMON;
    }
    if (!runtime->Shield->GetStatus(&metrics->Shield))
    {
        errno = ERR_RUNTIME_GET_STATUS_SHIELD;
    }

    // copy runtime metric
    mem_copy(&metrics->Core,  &runtime->RMCore,  sizeof(RT_Core));
    mem_copy(&metrics->Proc,  &runtime->RMProc,  sizeof(RT_Proc));
    mem_copy(&metrics->Sleep, &runtime->RMSleep, sizeof(RT_SleepM));

    if (!rt_unlock())
    {
        return ERR_RUNTIME_UNLOCK;
    }
    return errno;
}

__declspec(noinline)
errno RT_Cleanup()
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return ERR_RUNTIME_LOCK;
    }
    errno errlm = RT_lock_mods();
    if (errlm != NO_ERROR)
    {
        return errlm;
    }

    // maybe some libraries will use the tracked
    // memory page or heap, so free memory after
    // free all library.
    errno err = NO_ERROR;
    typedef errno (*submodule_t)();
    submodule_t submodules[] =
    {
        // first kill all threads
        runtime->ThreadTracker->KillAll,

        // high-level modules
        runtime->WinHTTP->Clean,
        runtime->WinCrypto->Clean,

        // runtime submodules
        runtime->ResourceTracker->FreeAll,
        runtime->LibraryTracker->FreeAll,
        runtime->MemoryTracker->FreeAll,
    };
    errno enmod = NO_ERROR;
    for (int i = 0; i < arrlen(submodules); i++)
    {
        enmod = submodules[i]();
        if (enmod != NO_ERROR && err == NO_ERROR)
        {
            err = enmod;
        }
    }
    // erase data in the large stack
    mem_init(submodules, sizeof(submodules));

    // flush Windows API cache without mutex
    runtime->MemoryTracker->Flush();
    runtime->ResourceTracker->Flush();

    recoverProcessEnv(runtime);

    errno errum = RT_unlock_mods();
    if (errum != NO_ERROR)
    {
        return errum;
    }
    if (!rt_unlock())
    {
        return ERR_RUNTIME_UNLOCK;
    }
    return err;
}

__declspec(noinline)
errno RT_Exit()
{
    return RT_StopStub(false, 0);
}

__declspec(noinline)
void RT_Stop(uint32 code)
{
    RT_StopStub(true, code);
}

__declspec(noinline)
errno RT_StopStub(bool exitThread, uint32 code)
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock())
    {
        return ERR_RUNTIME_LOCK;
    }
    errno errlm = RT_lock_mods();
    if (errlm != NO_ERROR)
    {
        return errlm;
    }

    errno error = NO_ERROR;

    // maybe some libraries will use the tracked
    // memory page or heap, so free memory after
    // free all library.
    typedef errno (*submodule_t)();
    submodule_t submodules[] =
    {
        // reliability modules
        runtime->Sysmon->Stop,
        runtime->Watchdog->Stop,

        // kill all threads
        runtime->ThreadTracker->Clean,

        // high-level modules
        runtime->WinCrypto->Uninstall,
        runtime->WinHTTP->Uninstall,
        runtime->WinFile->Uninstall,
        runtime->WinBase->Uninstall,

        // runtime submodules
        runtime->InMemoryStorage->Clean,
        runtime->ArgumentStore->Clean,
        runtime->ResourceTracker->Clean,
        runtime->LibraryTracker->Clean,
        runtime->MemoryTracker->Clean,

        // security module
        runtime->Detector->Stop,
    };
    errno enmod = NO_ERROR;
    for (int i = 0; i < arrlen(submodules); i++)
    {
        enmod = submodules[i]();
        if (enmod != NO_ERROR && error == NO_ERROR)
        {
            error = enmod;
        }
    }
    // erase data in the large stack
    mem_init(submodules, sizeof(submodules));

    recoverProcessEnv(runtime);

    // clean runtime resource
    errno enclr = cleanRuntimeResource(runtime, false);
    if (enclr != NO_ERROR && error == NO_ERROR)
    {
        error = enclr;
    }

    // if need exit thread, delegate to shield
    if (exitThread)
    {
        // force set thread exit code to zero
        if (runtime->Options.EnableSecurityMode)
        {
            code = 0;
        }
        runtime->Shield->Stop(code);
        // unreachable code
        return error;
    }

    // clean resource about shield
    errno ensdc = runtime->Shield->Clean();
    if (ensdc != NO_ERROR && error == NO_ERROR)
    {
        error = ensdc;
    }

    if (runtime->Options.NotEraseInstruction)
    {
        rs_erase((uintptr)(runtime->MainMemPage), MAIN_MEM_PAGE_SIZE);
        return error;
    }

    // adjust protect for erase instruction
    DWORD oldProtect;
    if (!adjustPageProtect(runtime, &oldProtect))
    {
        return ERR_RUNTIME_ADJUST_PROTECT;
    }

    // erase runtime instruction except these 
    uintptr begin = (uintptr)(GetFuncAddr(&InitRuntime));
    uintptr end   = (uintptr)(GetFuncAddr(&RT_Exit));
    rs_erase(begin, end - begin);
    begin = (uintptr)(GetFuncAddr(&rs_epilogue));
    end   = (uintptr)(GetFuncAddr(&Argument_Stub));
    rs_erase(begin, end - begin);

    // not call recoverPageProtect because
    // this function has been erased
    if (!runtime->Options.NotAdjustProtect)
    {
        LPVOID addr = runtime->Prologue;
        SIZE_T size = runtime->InstSize;
        DWORD  old;
        if (!runtime->VirtualProtect(addr, size, oldProtect, &old))
        {
            if (error == NO_ERROR)
            {
                error = ERR_RUNTIME_RECOVER_PROTECT;
            }
        }
    }

    rs_erase((uintptr)(runtime->MainMemPage), MAIN_MEM_PAGE_SIZE);
    return error;
}

// these functions are provide to RT_StopStub.

// prevent it be linked to other functions.
#pragma optimize("", off)

__declspec(noinline)
static void rs_erase(uintptr address, uintptr size)
{
    byte* buf = (byte*)address;
    for (uint i = 0; i < size; i++)
    {
        buf[i] = buf[i] & 0;
    }
}

#pragma warning(push)
#pragma warning(disable: 4189)
static void rs_epilogue()
{
    byte var = 1;
    return;
}
#pragma warning(pop)

#pragma optimize("", on)
