//go:build windows

package gleamrt

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/RTS-Framework/GRT-Develop/hashmod"
	"github.com/RTS-Framework/GRT-Develop/info"
	"github.com/RTS-Framework/GRT-Develop/metric"
)

// Handle is the pseudo handle for GleamRT.
const Handle = windows.Handle(0x00001234)

var (
	modGleamRT = windows.NewLazyDLL("GleamRT.dll")

	procInitialize   = modGleamRT.NewProc("RT_Initialize")
	procUninitialize = modGleamRT.NewProc("RT_Uninitialize")

	procGetProcAddress    = modGleamRT.NewProc("RT_GetProcAddress")
	procGetProcAddressEx  = modGleamRT.NewProc("RT_GetProcAddressEx")
	procGetProcAddressRaw = modGleamRT.NewProc("RT_GetProcAddressRaw")

	procGetTEB = modGleamRT.NewProc("RT_GetTEB")
	procGetPEB = modGleamRT.NewProc("RT_GetPEB")
	procGetPML = modGleamRT.NewProc("RT_GetPML")

	procGetOptions  = modGleamRT.NewProc("RT_GetOptions")
	procGetRuntimeM = modGleamRT.NewProc("RT_GetRuntimeM")
	procGetInfo     = modGleamRT.NewProc("RT_GetInfo")
	procGetMetrics  = modGleamRT.NewProc("RT_GetMetrics")

	procSleepHR = modGleamRT.NewProc("RT_SleepHR")

	procSleep       = modGleamRT.NewProc("RT_Sleep")
	procExitProcess = modGleamRT.NewProc("RT_ExitProcess")
)

// IsLoadDLL is used to check current program is load runtime dll.
func IsLoadDLL() bool {
	return modGleamRT.Load() == nil
}

// IsOnRuntime is used to detect current program is running above runtime.
func IsOnRuntime() bool {
	if !IsLoadDLL() {
		return false
	}
	return modGleamRT.Handle() == uintptr(Handle)
}

// Initialize is used to call InitRuntime (only for test runtime package).
func Initialize(opts *Options) error {
	if opts == nil {
		opts = new(Options)
	}
	// for test Image Pinning
	path, err := os.Executable()
	if err != nil {
		return err
	}
	opts.ImagePinningHash = hashmod.Hash(filepath.Base(path))
	// initialize runtime
	ret, _, err := procInitialize.Call(uintptr(unsafe.Pointer(opts))) // #nosec
	if ret == 0 {
		en := uintptr(err.(syscall.Errno))
		return fmt.Errorf("failed to initialize runtime: 0x%08X", en)
	}
	return nil
}

// Uninitialize is used to exit runtime for free dll (only for test runtime package).
func Uninitialize() error {
	ret, _, err := procUninitialize.Call()
	if ret == 0 {
		en := uintptr(err.(syscall.Errno))
		return fmt.Errorf("failed to uninitialize runtime: 0x%08X", en)
	}
	return nil
}

// GetProcAddress is used to get procedure address.
func GetProcAddress(module windows.Handle, name string) (uintptr, error) {
	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	ret, _, err := procGetProcAddress.Call(
		uintptr(module), uintptr(unsafe.Pointer(namePtr)),
	) // #nosec
	if ret == 0 {
		en := uintptr(err.(syscall.Errno))
		return 0, fmt.Errorf("failed to call GetProcAddress: 0x%08X", en)
	}
	return ret, nil
}

// GetProcAddressEx is used to get procedure address with control redirect.
func GetProcAddressEx(module windows.Handle, name string, redirect bool) (uintptr, error) {
	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	ret, _, err := procGetProcAddressEx.Call(
		uintptr(module), uintptr(unsafe.Pointer(namePtr)), boolToUintptr(redirect),
	) // #nosec
	if ret == 0 {
		en := uintptr(err.(syscall.Errno))
		return 0, fmt.Errorf("failed to call GetProcAddressEx: 0x%08X", en)
	}
	return ret, nil
}

// GetProcAddressRaw is used to call original GetProcAddress.
func GetProcAddressRaw(module windows.Handle, name string) (uintptr, error) {
	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	ret, _, err := procGetProcAddressRaw.Call(
		uintptr(module), uintptr(unsafe.Pointer(namePtr)),
	) // #nosec
	if ret == 0 {
		en := uintptr(err.(syscall.Errno))
		return 0, fmt.Errorf("failed to call GetProcAddressRaw: 0x%08X", en)
	}
	return ret, nil
}

// GetTEB is used to get thread environment block.
func GetTEB() uintptr {
	ret, _, _ := procGetTEB.Call()
	return ret
}

// GetPEB is used to get process environment block.
func GetPEB() uintptr {
	ret, _, _ := procGetPEB.Call()
	return ret
}

// GetPML is used to get process module list.
func GetPML() uintptr {
	ret, _, _ := procGetPML.Call()
	return ret
}

// GetOptions is used to get runtime options.
func GetOptions() (*Options, error) {
	var opts Options
	ret, _, _ := procGetOptions.Call(uintptr(unsafe.Pointer(&opts))) // #nosec
	if ret != windows.NO_ERROR {
		return nil, fmt.Errorf("failed to call GetOptions: 0x%08X", ret)
	}
	return &opts, nil
}

// GetRuntimeM is used to get runtime module/method.
func GetRuntimeM() (*RuntimeM, error) {
	var rtm RuntimeM
	ret, _, _ := procGetRuntimeM.Call(uintptr(unsafe.Pointer(&rtm))) // #nosec
	if ret != windows.NO_ERROR {
		return nil, fmt.Errorf("failed to call GetRuntimeM: 0x%08X", ret)
	}
	return &rtm, nil
}

// GetInfo is used to get runtime information.
func GetInfo() (*Info, error) {
	var inf info.Info
	ret, _, _ := procGetInfo.Call(uintptr(unsafe.Pointer(&inf))) // #nosec
	if ret != windows.NO_ERROR {
		return nil, fmt.Errorf("failed to call GetInfo: 0x%08X", ret)
	}
	return ConvertRawInfo(&inf), nil
}

// GetMetrics is used to get runtime metrics.
func GetMetrics() (*Metrics, error) {
	var metrics metric.Metrics
	ret, _, _ := procGetMetrics.Call(uintptr(unsafe.Pointer(&metrics))) // #nosec
	if ret != windows.NO_ERROR {
		return nil, fmt.Errorf("failed to call GetMetrics: 0x%08X", ret)
	}
	return ConvertRawMetrics(&metrics), nil
}

// Sleep is used to hide and sleep, it is the core method.
func Sleep(d time.Duration) error {
	ret, _, _ := procSleepHR.Call(uintptr(d.Milliseconds())) // #nosec G115
	if ret != windows.NO_ERROR {
		return fmt.Errorf("failed to call Sleep: 0x%08X", ret)
	}
	return nil
}

// SleepSim is used to simulate kernel32.Sleep in Thread Tracker.
// But in Go, use time.Sleep is enough, this function is test only.
func SleepSim(d time.Duration) {
	_, _, _ = procSleep.Call(uintptr(d.Milliseconds())) // #nosec G115
}

// ExitProcess is used to call original ExitProcess.
func ExitProcess(code int) {
	_, _, _ = procExitProcess.Call(uintptr(code)) // #nosec G115
}

func boolToUintptr(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}
