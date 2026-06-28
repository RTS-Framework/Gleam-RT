//go:build windows

package shield

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/RTS-Framework/GRT-Develop/metric"
	"github.com/RTS-Framework/GRT-Develop/shield"
)

var (
	modGleamRT = windows.NewLazyDLL("GleamRT.dll")

	procStatus = modGleamRT.NewProc("SD_Status")
)

// Status contains shield status.
type Status struct {
	EntryPoint  uintptr `json:"entry_point"`
	BaseAddress uintptr `json:"base_address"`
	Source      string  `json:"source"`
}

// GetStatus is used to get shield status.
func GetStatus() (*Status, error) {
	var status metric.SDStatus
	ret, _, err := procStatus.Call(uintptr(unsafe.Pointer(&status))) // #nosec
	if ret == 0 {
		en := uintptr(err.(syscall.Errno))
		return nil, fmt.Errorf("failed to call shield.Status: 0x%08X", en)
	}
	s := Status{
		EntryPoint:  status.EntryPoint,
		BaseAddress: status.BaseAddress,
		Source:      shield.ConvertSource(status.Source),
	}
	return &s, nil
}
