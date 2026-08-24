//go:build windows

package detector

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/RTS-Framework/GRT-Develop/metric"
)

var (
	modGleamRT = windows.NewLazyDLL("GleamRT.dll")

	procDetect    = modGleamRT.NewProc("DT_Detect")
	procGetStatus = modGleamRT.NewProc("DT_GetStatus")
)

// Status contains detector status.
type Status struct {
	IsEnabled        bool  `json:"is_enabled"`
	HasDebugger      bool  `json:"has_debugger"`
	HasMemoryScanner bool  `json:"has_memory_scanner"`
	InSandbox        bool  `json:"in_sandbox"`
	InVirtualMachine bool  `json:"in_virtual_machine"`
	InEmulator       bool  `json:"in_emulator"`
	IsAccelerated    bool  `json:"is_accelerated"`
	SafeRank         int32 `json:"safe_rank"`
	NumDetectCalls   int64 `json:"num_detect_calls"`
}

// Detect is used to detect current environment.
func Detect() error {
	ret, _, err := procDetect.Call()
	if ret == 0 {
		en := uintptr(err.(syscall.Errno))
		return fmt.Errorf("failed to call detector.Detect: 0x%08X", en)
	}
	return nil
}

// GetStatus is used to get detector status.
func GetStatus() (*Status, error) {
	var status metric.DTStatus
	ret, _, err := procGetStatus.Call(uintptr(unsafe.Pointer(&status))) // #nosec
	if ret == 0 {
		en := uintptr(err.(syscall.Errno))
		return nil, fmt.Errorf("failed to call detector.GetStatus: 0x%08X", en)
	}
	s := Status{
		IsEnabled:        status.IsEnabled.ToBool(),
		HasDebugger:      status.HasDebugger.ToBool(),
		HasMemoryScanner: status.HasMemoryScanner.ToBool(),
		InSandbox:        status.InSandbox.ToBool(),
		InVirtualMachine: status.InVirtualMachine.ToBool(),
		InEmulator:       status.InEmulator.ToBool(),
		IsAccelerated:    status.IsAccelerated.ToBool(),
		SafeRank:         status.SafeRank,
		NumDetectCalls:   status.NumDetectCalls,
	}
	return &s, nil
}
