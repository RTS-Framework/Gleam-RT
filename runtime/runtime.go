//go:build windows

package gleamrt

import (
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/RTS-Framework/GRT-Develop/info"
	"github.com/RTS-Framework/GRT-Develop/metric"
	"github.com/RTS-Framework/GRT-Develop/types"
)

const (
	null    = 0
	noError = 0
)

type errno struct {
	method string
	errno  uintptr
}

func (e *errno) Error() string {
	return fmt.Sprintf("RuntimeM.%s return errno: 0x%08X", e.method, e.errno)
}

// Options contains options about initialize runtime.
type Options struct {
	ImagePinningHash    uint64
	ShieldModuleHash    uint64
	ShieldEntryPoint    uint64
	ShieldMemAddress    uint64
	EnableSecurityMode  types.BOOL
	DisableDetector     types.BOOL
	DisableWatchdog     types.BOOL
	DisableSysmon       types.BOOL
	NotEraseInstruction types.BOOL
	NotAdjustProtect    types.BOOL
	TrackCurrentThread  types.BOOL
}

// RuntimeM contains exported methods of runtime.
// Only the Data section is data, otherwise method.
type RuntimeM struct {
	HashAPI struct {
		FindModMH  uintptr
		FindAPIMA  uintptr
		FindAPIMH  uintptr
		FindModMHL uintptr
		FindAPIMAL uintptr
		FindAPIMHL uintptr
		FindModA   uintptr
		FindModW   uintptr
		FindAPIA   uintptr
		FindAPIW   uintptr
	}

	Library struct {
		LoadA   uintptr
		LoadW   uintptr
		LoadExA uintptr
		LoadExW uintptr
		Free    uintptr
		GetProc uintptr

		Lock    uintptr
		Unlock  uintptr
		Status  uintptr
		FreeAll uintptr
	}

	Memory struct {
		Alloc   uintptr
		Calloc  uintptr
		Realloc uintptr
		Free    uintptr
		Size    uintptr
		Cap     uintptr

		Lock    uintptr
		Unlock  uintptr
		Status  uintptr
		FreeAll uintptr
	}

	Thread struct {
		New   uintptr
		Exit  uintptr
		Sleep uintptr

		Lock    uintptr
		Unlock  uintptr
		Status  uintptr
		KillAll uintptr
	}

	Resource struct {
		LockMutex           uintptr
		UnlockMutex         uintptr
		LockEvent           uintptr
		UnlockEvent         uintptr
		LockSemaphore       uintptr
		UnlockSemaphore     uintptr
		LockWaitableTimer   uintptr
		UnlockWaitableTimer uintptr
		LockFile            uintptr
		UnlockFile          uintptr

		Status  uintptr
		FreeAll uintptr
	}

	Argument struct {
		GetValue   uintptr
		GetPointer uintptr
		Erase      uintptr
		EraseAll   uintptr
		Status     uintptr
	}

	Storage struct {
		SetValue   uintptr
		GetValue   uintptr
		GetPointer uintptr
		Delete     uintptr
		DeleteAll  uintptr
		Status     uintptr
	}

	WinBase struct {
		ANSIToUTF16  uintptr
		UTF16ToANSI  uintptr
		ANSIToUTF16N uintptr
		UTF16ToANSIN uintptr
	}

	WinFile struct {
		ReadFileA  uintptr
		ReadFileW  uintptr
		WriteFileA uintptr
		WriteFileW uintptr
	}

	WinHTTP struct {
		Init uintptr
		Get  uintptr
		Post uintptr
		Do   uintptr

		FreeDLL uintptr
	}

	WinCrypto struct {
		RandBuffer uintptr
		Hash       uintptr
		HMAC       uintptr
		AESEncrypt uintptr
		AESDecrypt uintptr
		RSAGenKey  uintptr
		RSAPubKey  uintptr
		RSASign    uintptr
		RSAVerify  uintptr
		RSAEncrypt uintptr
		RSADecrypt uintptr

		FreeDLL uintptr
	}

	Random struct {
		Seed     uintptr
		Int      uintptr
		Int8     uintptr
		Int16    uintptr
		Int32    uintptr
		Int64    uintptr
		Uint     uintptr
		Uint8    uintptr
		Uint16   uintptr
		Uint32   uintptr
		Uint64   uintptr
		IntN     uintptr
		Int8N    uintptr
		Int16N   uintptr
		Int32N   uintptr
		Int64N   uintptr
		UintN    uintptr
		Uint8N   uintptr
		Uint16N  uintptr
		Uint32N  uintptr
		Uint64N  uintptr
		Byte     uintptr
		Bool     uintptr
		BOOL     uintptr
		Buffer   uintptr
		Sequence uintptr
	}

	Encoding struct {
		Hex struct {
			Encode uintptr
			Decode uintptr
		}

		Base64 struct {
			Encode uintptr
			Decode uintptr
		}
	}

	Hash struct {
		SHA256 struct {
			New  uintptr
			Hash uintptr
		}
	}

	Crypto struct {
		XORBuffer        uintptr
		SubstituteBuffer uintptr
		ShuffleBuffer    uintptr
		EraseBuffer      uintptr
		EraseInstruction uintptr
	}

	Compressor struct {
		Compress   uintptr
		Decompress uintptr
	}

	Serialization struct {
		Serialize   uintptr
		Unserialize uintptr
	}

	MemScanner struct {
		ScanByValue  uintptr
		ScanByConfig uintptr
		BinToPattern uintptr
	}

	Detector struct {
		Detect uintptr
		Status uintptr
	}

	Watchdog struct {
		SetHandler uintptr
		SetTimeout uintptr
		Kick       uintptr
		Enable     uintptr
		Disable    uintptr
		IsEnabled  uintptr
		Status     uintptr

		_ uintptr
		_ uintptr
	}

	Sysmon struct {
		Status uintptr

		_ uintptr
		_ uintptr
	}

	Shield struct {
		Status uintptr

		_ uintptr
		_ uintptr
	}

	Env struct {
		TEB uintptr
		PEB uintptr
		PML uintptr
	}

	DLL struct {
		MainEXE  uintptr
		Kernel32 uintptr
		Ntdll    uintptr
	}

	Raw struct {
		GetProcAddress uintptr
		ExitProcess    uintptr
	}

	Core struct {
		Sleep   uintptr
		Hide    uintptr
		Recover uintptr
		Options uintptr
		Info    uintptr
		Metrics uintptr
		Cleanup uintptr
		Exit    uintptr
		Stop    uintptr
	}

	Data struct {
		Mutex uintptr
	}
}

// NewRuntime is used to create RuntimeM from initialized instance.
// It will copy memory for prevent runtime encrypt memory page when
// call runtime methods or call SleepHR.
func NewRuntime(ptr uintptr) *RuntimeM {
	rt := *(*RuntimeM)(unsafe.Pointer(ptr)) // #nosec
	return &rt
}

// InitRuntime is used to initialize runtime from instance.
// Each runtime instance can only initialize once.
func InitRuntime(inst uintptr, opts *Options) (*RuntimeM, error) {
	ptr, _, err := syscall.SyscallN(inst, 0, uintptr(unsafe.Pointer(opts))) // #nosec
	if ptr == null {
		return nil, fmt.Errorf("failed to initialize runtime: 0x%08X", uint(err))
	}
	return NewRuntime(ptr), nil
}

func (rt *RuntimeM) lock() {
	runtime.LockOSThread()
	hMutex := windows.Handle(rt.Data.Mutex)
	_, err := windows.WaitForSingleObject(hMutex, windows.INFINITE)
	if err != nil {
		panic(fmt.Sprintf("failed to lock runtime mutex: %s", err))
	}
}

func (rt *RuntimeM) unlock() {
	hMutex := windows.Handle(rt.Data.Mutex)
	err := windows.ReleaseMutex(hMutex)
	if err != nil {
		panic(fmt.Sprintf("failed to release runtime mutex: %s", err))
	}
	runtime.UnlockOSThread()
}

// Sleep is used to sleep and hide runtime.
func (rt *RuntimeM) Sleep(d time.Duration) error {
	rt.lock()
	defer rt.unlock()
	ret, _, _ := syscall.SyscallN(rt.Core.Sleep, uintptr(d.Milliseconds())) // #nosec G115
	if ret != noError {
		return &errno{method: "Core.Sleep", errno: ret}
	}
	return nil
}

// Options is used to get runtime options.
func (rt *RuntimeM) Options() (*Options, error) {
	rt.lock()
	defer rt.unlock()
	var opts Options
	ret, _, _ := syscall.SyscallN(rt.Core.Options, uintptr(unsafe.Pointer(&opts))) // #nosec
	if ret != noError {
		return nil, &errno{method: "Core.Options", errno: ret}
	}
	return &opts, nil
}

// Information is used to get runtime information.
func (rt *RuntimeM) Information() (*Info, error) {
	rt.lock()
	defer rt.unlock()
	var inf info.Info
	ret, _, _ := syscall.SyscallN(rt.Core.Info, uintptr(unsafe.Pointer(&inf))) // #nosec
	if ret != noError {
		return nil, &errno{method: "Core.Info", errno: ret}
	}
	return ConvertRawInfo(&inf), nil
}

// Metrics is used to get runtime metric about core modules.
func (rt *RuntimeM) Metrics() (*Metrics, error) {
	rt.lock()
	defer rt.unlock()
	var metrics metric.Metrics
	ret, _, _ := syscall.SyscallN(rt.Core.Metrics, uintptr(unsafe.Pointer(&metrics))) // #nosec
	if ret != noError {
		return nil, &errno{method: "Core.Metrics", errno: ret}
	}
	return ConvertRawMetrics(&metrics), nil
}

// Cleanup is used to clean all tracked object except locked.
func (rt *RuntimeM) Cleanup() error {
	rt.lock()
	defer rt.unlock()
	ret, _, _ := syscall.SyscallN(rt.Core.Cleanup) // #nosec
	if ret != noError {
		return &errno{method: "Core.Cleanup", errno: ret}
	}
	return nil
}

// Exit is used to exit runtime.
func (rt *RuntimeM) Exit() error {
	rt.lock()
	// defer rt.unlock() runtime will close the mutex handle.
	ret, _, _ := syscall.SyscallN(rt.Core.Exit) // #nosec
	if ret != noError {
		return &errno{method: "Core.Exit", errno: ret}
	}
	return nil
}
