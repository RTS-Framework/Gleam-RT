//go:build windows

package gleamrt

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/RTS-Framework/GRT-Develop/types"
)

func init() {
	var src string
	switch runtime.GOARCH {
	case "386":
		src = "../dist/GleamRT_x86.dll"
	case "amd64":
		src = "../dist/GleamRT_x64.dll"
	}
	dll, err := os.ReadFile(src)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile("GleamRT.dll", dll, 0644)
	if err != nil {
		panic(err)
	}
}

func TestMain(m *testing.M) {
	opts := Options{
		NotEraseInstruction: types.TRUE,
	}
	err := Initialize(&opts)
	if err != nil {
		panic(err)
	}

	code := m.Run()

	err = Uninitialize()
	if err != nil {
		panic(err)
	}

	err = windows.FreeLibrary(windows.Handle(modGleamRT.Handle()))
	if err != nil {
		panic(err)
	}
	err = os.Remove("GleamRT.dll")
	if err != nil {
		panic(err)
	}

	os.Exit(code)
}

func TestInitialize(t *testing.T) {
	err := Initialize(nil)
	require.NoError(t, err)
}

func TestIsLoadDLL(t *testing.T) {
	require.True(t, IsLoadDLL())
}

func TestIsOnRuntime(t *testing.T) {
	require.False(t, IsOnRuntime())
}

func TestGetProcAddress(t *testing.T) {
	hKernel32, err := windows.LoadLibrary("kernel32.dll")
	require.NoError(t, err)

	VirtualAlloc, err := windows.GetProcAddress(hKernel32, "VirtualAlloc")
	require.NoError(t, err)

	t.Run("redirected", func(t *testing.T) {
		proc, err := GetProcAddress(hKernel32, "VirtualAlloc")
		require.NoError(t, err)
		require.NotEqual(t, VirtualAlloc, proc)
	})

	t.Run("procedure not found", func(t *testing.T) {
		proc, err := GetProcAddress(hKernel32, "NotFound")
		require.EqualError(t, err, "failed to call GetProcAddress: 0x0000007F")
		require.Zero(t, proc)
	})

	t.Run("method not found", func(t *testing.T) {
		proc, err := GetProcAddress(Handle, "NotFound")
		require.EqualError(t, err, "failed to call GetProcAddress: 0xFF000302")
		require.Zero(t, proc)
	})

	metrics, err := GetMetrics()
	require.NoError(t, err)

	require.NotZero(t, metrics.Proc.NumCalls)
	require.NotZero(t, metrics.Proc.NumRedirect)
}

func TestGetProcAddressEx(t *testing.T) {
	hKernel32, err := windows.LoadLibrary("kernel32.dll")
	require.NoError(t, err)

	VirtualAlloc, err := windows.GetProcAddress(hKernel32, "VirtualAlloc")
	require.NoError(t, err)

	t.Run("redirected", func(t *testing.T) {
		proc, err := GetProcAddressEx(hKernel32, "VirtualAlloc", true)
		require.NoError(t, err)
		require.NotEqual(t, VirtualAlloc, proc)
	})

	t.Run("not redirected", func(t *testing.T) {
		proc, err := GetProcAddressEx(hKernel32, "VirtualAlloc", false)
		require.NoError(t, err)
		require.Equal(t, VirtualAlloc, proc)
	})

	t.Run("not found", func(t *testing.T) {
		proc, err := GetProcAddressEx(hKernel32, "NotFound", false)
		require.EqualError(t, err, "failed to call GetProcAddressEx: 0x0000007F")
		require.Zero(t, proc)
	})

	metrics, err := GetMetrics()
	require.NoError(t, err)

	require.NotZero(t, metrics.Proc.NumCalls)
	require.NotZero(t, metrics.Proc.NumRedirect)
}

func TestGetProcAddressRaw(t *testing.T) {
	hKernel32, err := windows.LoadLibrary("kernel32.dll")
	require.NoError(t, err)

	t.Run("common", func(t *testing.T) {
		VirtualAlloc, err := windows.GetProcAddress(hKernel32, "VirtualAlloc")
		require.NoError(t, err)

		proc, err := GetProcAddressRaw(hKernel32, "VirtualAlloc")
		require.NoError(t, err)
		require.Equal(t, VirtualAlloc, proc)
	})

	t.Run("not found", func(t *testing.T) {
		proc, err := GetProcAddressRaw(hKernel32, "NotFound")
		require.EqualError(t, err, "failed to call GetProcAddressRaw: 0x0000007F")
		require.Zero(t, proc)
	})

	metrics, err := GetMetrics()
	require.NoError(t, err)

	require.Equal(t, int64(2), metrics.Proc.NumRawProc)
}

func TestGetRuntimeMethod(t *testing.T) {
	hGleamRT := windows.Handle(modGleamRT.Handle())

	for _, proc := range []string{
		"RT_GetProcAddress",
		"RT_GetProcAddressEx",
		"RT_GetProcAddressRaw",

		"RT_GetTEB",
		"RT_GetPEB",
		"RT_GetPML",

		"RT_GetOptions",
		"RT_GetRuntimeM",
		"RT_GetInfo",
		"RT_GetMetrics",
		"RT_SleepHR",

		"RT_Sleep",
		"RT_ExitProcess",

		"AS_GetValue",
		"AS_GetPointer",
		"AS_Erase",
		"AS_EraseAll",
		"AS_GetStatus",

		"IS_SetValue",
		"IS_GetValue",
		"IS_GetPointer",
		"IS_Delete",
		"IS_DeleteAll",
		"IS_GetStatus",

		"DT_Detect",
		"DT_GetStatus",

		"WD_SetHandler",
		"WD_SetTimeout",
		"WD_Kick",
		"WD_Enable",
		"WD_Disable",
		"WD_IsEnabled",
		"WD_GetStatus",

		"SM_GetStatus",

		"SD_GetStatus",
	} {
		dllProcAddr := modGleamRT.NewProc(proc).Addr()
		getProcAddr, err := windows.GetProcAddress(hGleamRT, proc)
		require.NoError(t, err, proc)
		require.Equal(t, dllProcAddr, getProcAddr)
		fmt.Printf("%s: 0x%X\n", proc, dllProcAddr)
	}
}

func TestGetTEB(t *testing.T) {
	teb := GetTEB()
	require.NotZero(t, teb)
}

func TestGetPEB(t *testing.T) {
	peb := windows.RtlGetCurrentPeb()
	expect := uintptr(unsafe.Pointer(peb)) // #nosec
	actual := GetPEB()
	require.Equal(t, expect, actual)
}

func TestGetPML(t *testing.T) {
	actual := GetPML()

	peb := windows.RtlGetCurrentPeb()
	addr := uintptr(unsafe.Pointer(peb)) // #nosec

	t.Run("x86", func(t *testing.T) {
		if runtime.GOARCH != "386" {
			return
		}

		ldr := *(*uintptr)(unsafe.Pointer(addr + 0x0C)) // #nosec
		pml := (ldr + 0x14) - 0x08
		require.Equal(t, pml, actual)
	})

	t.Run("x64", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			return
		}

		ldr := *(*uintptr)(unsafe.Pointer(addr + 0x18)) // #nosec
		pml := (ldr + 0x20) - 0x10
		require.Equal(t, pml, actual)
	})
}

func TestGetOptions(t *testing.T) {
	opts, err := GetOptions()
	require.NoError(t, err)

	// skip compare this field
	opts.ImagePinningHash = 0

	expected := &Options{
		NotEraseInstruction: types.TRUE,
	}
	require.Equal(t, expected, opts)
}

func TestGetRuntimeM(t *testing.T) {
	rtm, err := GetRuntimeM()
	require.NoError(t, err)
	require.NotZero(t, rtm)

	spew.Dump(rtm)
}

func TestGetInfo(t *testing.T) {
	info, err := GetInfo()
	require.NoError(t, err)
	spew.Dump(info)
}

func TestGetMetrics(t *testing.T) {
	metrics, err := GetMetrics()
	require.NoError(t, err)
	spew.Dump(metrics)
}

func TestSleep(t *testing.T) {
	now := time.Now()

	err := Sleep(time.Second)
	require.NoError(t, err)

	d := time.Since(now)
	require.Greater(t, d, time.Second)
}

func TestSleepSim(t *testing.T) {
	now := time.Now()

	SleepSim(time.Second)

	d := time.Since(now)
	require.Greater(t, d, time.Second)
}
