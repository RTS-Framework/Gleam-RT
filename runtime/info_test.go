//go:build windows

package gleamrt

import (
	"fmt"
	"runtime"
	"syscall"
	"testing"
	"unsafe"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"

	"github.com/RTS-Framework/GRT-Develop"
	"github.com/RTS-Framework/GRT-Develop/info"
)

func TestConvertRawInfo(t *testing.T) {
	// load runtime instance
	var template []byte
	switch runtime.GOARCH {
	case "386":
		template = testTemplateX86
	case "amd64":
		template = testTemplateX64
	default:
		t.Fatal("unsupported architecture")
	}
	instance, err := develop.Instantiate(template, nil)
	require.NoError(t, err)

	addr := loadInstance(t, instance)
	fmt.Printf("Runtime: 0x%X\n", addr)

	Runtime, err := InitRuntime(addr, nil)
	require.NoError(t, err)

	inf := info.Info{}
	ret, _, _ := syscall.SyscallN(
		Runtime.Core.Info, uintptr(unsafe.Pointer(&inf)),
	) // #nosec
	require.Zero(t, ret)

	i := ConvertRawInfo(&inf)
	spew.Dump(i)
	require.Equal(t, testVersion, i.Version)
}
