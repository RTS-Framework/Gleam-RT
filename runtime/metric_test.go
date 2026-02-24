//go:build windows

package gleamrt

import (
	"fmt"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"

	"github.com/RTS-Framework/GRT-Develop/metric"
)

func TestConvertRawMetrics(t *testing.T) {
	// load runtime shellcode
	var sc []byte
	switch runtime.GOARCH {
	case "386":
		sc = testRTx86
	case "amd64":
		sc = testRTx64
	default:
		t.Fatal("unsupported architecture")
	}
	addr := loadShellcode(t, sc)
	fmt.Printf("Runtime: 0x%X\n", addr)

	Runtime, err := InitRuntime(addr, nil)
	require.NoError(t, err)
	time.Sleep(time.Second)

	metrics := metric.Metrics{}
	ret, _, _ := syscall.SyscallN(
		Runtime.Core.Metrics, uintptr(unsafe.Pointer(&metrics)),
	) // #nosec
	require.Zero(t, ret)

	m := ConvertRawMetrics(&metrics)
	spew.Dump(m)
	require.NotZero(t, m.Sysmon.NumNormal)
}
