//go:build windows

package argument

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/RTS-Framework/GRT-Develop/metric"
)

var (
	modGleamRT = windows.NewLazyDLL("GleamRT.dll")

	procGetValue   = modGleamRT.NewProc("AS_GetValue")
	procGetPointer = modGleamRT.NewProc("AS_GetPointer")
	procErase      = modGleamRT.NewProc("AS_Erase")
	procEraseAll   = modGleamRT.NewProc("AS_EraseAll")
	procGetStatus  = modGleamRT.NewProc("AS_GetStatus")
)

// Status contains argument store status.
type Status struct {
	NumItems  int `json:"num_items"`
	NumErased int `json:"num_erased"`
	TotalSize int `json:"total_size"`
}

// GetValue is used to get argument value by id.
func GetValue(id uint32) ([]byte, bool) {
	var size uint32
	ret, _, _ := procGetValue.Call(
		uintptr(id), 0, uintptr(unsafe.Pointer(&size)),
	) // #nosec
	if ret == 0 {
		return nil, false
	}
	if size == 0 {
		return nil, true
	}
	value := make([]byte, size)
	ret, _, _ = procGetValue.Call(
		uintptr(id), uintptr(unsafe.Pointer(&value[0])), uintptr(unsafe.Pointer(&size)),
	) // #nosec
	if ret == 0 {
		return nil, false
	}
	return value, true
}

// GetPointer is used to get argument pointer by id.
func GetPointer(id uint32) (uintptr, uint32, bool) {
	var (
		ptr  uintptr
		size uint32
	)
	ret, _, _ := procGetPointer.Call(
		uintptr(id), uintptr(unsafe.Pointer(&ptr)), uintptr(unsafe.Pointer(&size)),
	) // #nosec
	if ret == 0 {
		return 0, 0, false
	}
	return ptr, size, true
}

// Erase is used to erase argument by id.
func Erase(id uint32) bool {
	ret, _, _ := procErase.Call(uintptr(id))
	return ret != 0
}

// EraseAll is used to erase all arguments.
func EraseAll() {
	_, _, _ = procEraseAll.Call()
}

// GetStatus is used to get argument status.
func GetStatus() (*Status, error) {
	var status metric.ASStatus
	ret, _, err := procGetStatus.Call(uintptr(unsafe.Pointer(&status))) // #nosec
	if ret == 0 {
		en := uintptr(err.(syscall.Errno))
		return nil, fmt.Errorf("failed to call argument.GetStatus: 0x%08X", en)
	}
	s := Status{
		NumItems:  int(status.NumItems),
		NumErased: int(status.NumErased),
		TotalSize: int(status.TotalSize),
	}
	return &s, nil
}
