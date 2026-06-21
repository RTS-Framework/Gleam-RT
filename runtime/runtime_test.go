//go:build windows

package gleamrt

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/RTS-Framework/GRT-Develop"
	"github.com/RTS-Framework/GRT-Develop/metric"
)

const testVersion = "v0.9.1"

var (
	testTemplateX86 []byte
	testTemplateX64 []byte
)

func init() {
	var err error
	testTemplateX86, err = os.ReadFile("../dist/GleamRT_x86.bin")
	if err != nil {
		panic(err)
	}
	testTemplateX64, err = os.ReadFile("../dist/GleamRT_x64.bin")
	if err != nil {
		panic(err)
	}
}

func TestRuntime(t *testing.T) {
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

	opts := Options{
		NotAdjustProtect: metric.TRUE,
	}
	Runtime, err := InitRuntime(addr, &opts)
	require.NoError(t, err)

	t.Run("Sleep", func(t *testing.T) {
		now := time.Now()

		err = Runtime.Sleep(time.Second)
		require.NoError(t, err)

		require.GreaterOrEqual(t, time.Since(now).Milliseconds(), int64(1000))
	})

	t.Run("Information", func(t *testing.T) {
		info, err := Runtime.Information()
		require.NoError(t, err)
		spew.Dump(info)
		require.Equal(t, testVersion, info.Version)
	})

	t.Run("Metrics", func(t *testing.T) {
		mem, _, en := syscall.SyscallN(Runtime.Memory.Alloc, 8192)
		if mem == 0 {
			t.Fatal(en)
		}

		metrics, err := Runtime.Metrics()
		require.NoError(t, err)
		spew.Dump(metrics)
		require.Equal(t, int64(1), metrics.Memory.NumRegions)
		require.Equal(t, int64(3), metrics.Memory.NumPages)
		require.NotZero(t, metrics.Sysmon.NumNormal)

		ret, _, en := syscall.SyscallN(Runtime.Memory.Free, mem)
		if ret != 1 {
			t.Fatal(en)
		}

		metrics, err = Runtime.Metrics()
		require.NoError(t, err)
		spew.Dump(metrics)
		require.Zero(t, metrics.Memory.NumRegions)
		require.Zero(t, metrics.Memory.NumPages)
		require.NotZero(t, metrics.Sysmon.NumNormal)
	})

	t.Run("Cleanup", func(t *testing.T) {
		mem, _, en := syscall.SyscallN(Runtime.Memory.Alloc, 8192)
		if mem == 0 {
			t.Fatal(en)
		}

		err = Runtime.Cleanup()
		require.NoError(t, err)

		metrics, err := Runtime.Metrics()
		require.NoError(t, err)
		require.Zero(t, metrics.Memory.NumRegions)
		require.Zero(t, metrics.Memory.NumPages)
		require.NotZero(t, metrics.Sysmon.NumNormal)
	})

	err = Runtime.Exit()
	require.NoError(t, err)
}

func loadInstance(t *testing.T, inst []byte) uintptr {
	size := uintptr(len(inst))
	mType := uint32(windows.MEM_COMMIT | windows.MEM_RESERVE)
	mProtect := uint32(windows.PAGE_EXECUTE_READWRITE)
	addr, err := windows.VirtualAlloc(0, size, mType, mProtect)
	require.NoError(t, err)
	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)
	copy(dst, inst)
	return addr
}
