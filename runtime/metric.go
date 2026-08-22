package gleamrt

import (
	"github.com/RTS-Framework/GRT-Develop/metric"
	"github.com/RTS-Framework/GRT-Develop/shield"
)

// Metrics contains status about runtime submodules.
type Metrics struct {
	Library  LTStatus `json:"library"`
	Memory   MTStatus `json:"memory"`
	Thread   TTStatus `json:"thread"`
	Resource RTStatus `json:"resource"`
	Argument ASStatus `json:"argument"`
	Storage  ISStatus `json:"storage"`
	Detector DTStatus `json:"detector"`
	Watchdog WDStatus `json:"watchdog"`
	Sysmon   SMStatus `json:"sysmon"`
	Shield   SDStatus `json:"shield"`
	Core     RTCore   `json:"core"`
	Proc     RTProc   `json:"proc"`
	Sleep    RTSleep  `json:"sleep"`
}

// LTStatus contains status about library tracker.
type LTStatus struct {
	NumModules   int64 `json:"num_modules"`
	NumLoadCalls int64 `json:"num_load_calls"`
	NumFreeCalls int64 `json:"num_free_calls"`
}

// MTStatus contains status about memory tracker.
type MTStatus struct {
	NumGlobals int64 `json:"num_globals"`
	NumLocals  int64 `json:"num_locals"`
	NumBlocks  int64 `json:"num_blocks"`
	NumRegions int64 `json:"num_regions"`
	NumPages   int64 `json:"num_pages"`
	NumHeaps   int64 `json:"num_heaps"`
	NumRWXs    int64 `json:"num_rwxs"`
	TotalAlloc int64 `json:"total_alloc"`
	PeakAlloc  int64 `json:"peak_alloc"`
}

// TTStatus contains status about thread tracker.
type TTStatus struct {
	NumThreads   int64 `json:"num_threads"`
	NumTLSIndex  int64 `json:"num_tls_index"`
	NumCreated   int64 `json:"num_created"`
	NumExited    int64 `json:"num_exited"`
	NumLocked    int64 `json:"num_locked"`
	NumSuspended int64 `json:"num_suspended"`
}

// RTStatus contains status about resource tracker.
type RTStatus struct {
	NumMutexs         int64 `json:"num_mutexs"`
	NumEvents         int64 `json:"num_events"`
	NumSemaphores     int64 `json:"num_semaphores"`
	NumWaitableTimers int64 `json:"num_waitable_timers"`
	NumFiles          int64 `json:"num_files"`
	NumDirectories    int64 `json:"num_directories"`
	NumIOCPs          int64 `json:"num_iocps"`
	NumRegKeys        int64 `json:"num_reg_keys"`
	NumSockets        int64 `json:"num_sockets"`
}

// ASStatus contains status about argument store.
type ASStatus struct {
	NumItems  int `json:"num_items"`
	NumErased int `json:"num_erased"`
	TotalSize int `json:"total_size"`
}

// ISStatus contains status about in-memory storage.
type ISStatus struct {
	NumItems  int `json:"num_items"`
	TotalSize int `json:"total_size"`
}

// DTStatus contains status about detector.
type DTStatus struct {
	IsEnabled        bool  `json:"is_enabled"`
	HasDebugger      bool  `json:"has_debugger"`
	HasMemoryScanner bool  `json:"has_memory_scanner"`
	InSandbox        bool  `json:"in_sandbox"`
	InEmulator       bool  `json:"in_emulator"`
	InVirtualMachine bool  `json:"in_virtual_machine"`
	IsAccelerated    bool  `json:"is_accelerated"`
	SafeRank         int32 `json:"safe_rank"`
	NumDetectCalls   int64 `json:"num_detect_calls"`
}

// WDStatus contains status about watchdog.
type WDStatus struct {
	IsEnabled bool  `json:"is_enabled"`
	NumKick   int64 `json:"num_kick"`
	NumNormal int64 `json:"num_normal"`
	NumReset  int64 `json:"num_reset"`
}

// SMStatus contains status about sysmon.
type SMStatus struct {
	IsEnabled  bool  `json:"is_enabled"`
	NumNormal  int64 `json:"num_normal"`
	NumRecover int64 `json:"num_recover"`
	NumPanic   int64 `json:"num_panic"`
}

// SDStatus contains status about shield.
type SDStatus struct {
	EntryPoint  uintptr `json:"entry_point"`
	BaseAddress uintptr `json:"base_address"`
	Source      string  `json:"source"`
}

// RTCore contains metric about runtime core.
type RTCore struct {
	Uptime       int64 `json:"uptime"`
	InitElapsed  int64 `json:"init_elapsed"`
	SecurityMode bool  `json:"security_mode"`
	IsHealthy    bool  `json:"is_healthy"`
}

// RTProc contains metric about runtime GetProcAddress.
type RTProc struct {
	NumCalls    int64 `json:"num_calls"`
	NumRedirect int64 `json:"num_redirect"`
	NumFallback int64 `json:"num_fallback"`
	NumRTMethod int64 `json:"num_rt_method"`
	NumRawProc  int64 `json:"num_raw_proc"`
}

// RTSleep contains metric about runtime sleep.
type RTSleep struct {
	NumCalls         int64 `json:"num_calls"`
	LastPreElapsed   int32 `json:"last_pre_elapsed"`
	LastPostElapsed  int32 `json:"last_post_elapsed"`
	TotalPreElapsed  int64 `json:"total_pre_elapsed"`
	TotalPostElapsed int64 `json:"total_post_elapsed"`
	MinPreElapsed    int32 `json:"min_pre_elapsed"`
	MinPostElapsed   int32 `json:"min_post_elapsed"`
	MaxPreElapsed    int32 `json:"max_pre_elapsed"`
	MaxPostElapsed   int32 `json:"max_post_elapsed"`
	AvgPreElapsed    int32 `json:"avg_pre_elapsed"`
	AvgPostElapsed   int32 `json:"avg_post_elapsed"`
}

// ConvertRawMetrics is used to convert raw runtime metrics to go type.
func ConvertRawMetrics(metrics *metric.Metrics) *Metrics {
	return &Metrics{
		Library: LTStatus{
			NumModules:   metrics.Library.NumModules,
			NumLoadCalls: metrics.Library.NumLoadCalls,
			NumFreeCalls: metrics.Library.NumFreeCalls,
		},
		Memory: MTStatus{
			NumGlobals: metrics.Memory.NumGlobals,
			NumLocals:  metrics.Memory.NumLocals,
			NumBlocks:  metrics.Memory.NumBlocks,
			NumRegions: metrics.Memory.NumRegions,
			NumPages:   metrics.Memory.NumPages,
			NumHeaps:   metrics.Memory.NumHeaps,
			NumRWXs:    metrics.Memory.NumRWXs,
			TotalAlloc: metrics.Memory.TotalAlloc,
			PeakAlloc:  metrics.Memory.PeakAlloc,
		},
		Thread: TTStatus{
			NumThreads:   metrics.Thread.NumThreads,
			NumTLSIndex:  metrics.Thread.NumTLSIndex,
			NumCreated:   metrics.Thread.NumCreated,
			NumExited:    metrics.Thread.NumExited,
			NumLocked:    metrics.Thread.NumLocked,
			NumSuspended: metrics.Thread.NumSuspended,
		},
		Resource: RTStatus{
			NumMutexs:         metrics.Resource.NumMutexs,
			NumEvents:         metrics.Resource.NumEvents,
			NumSemaphores:     metrics.Resource.NumSemaphores,
			NumWaitableTimers: metrics.Resource.NumWaitableTimers,
			NumFiles:          metrics.Resource.NumFiles,
			NumDirectories:    metrics.Resource.NumDirectories,
			NumIOCPs:          metrics.Resource.NumIOCPs,
			NumRegKeys:        metrics.Resource.NumRegKeys,
			NumSockets:        metrics.Resource.NumSockets,
		},
		Argument: ASStatus{
			NumItems:  int(metrics.Argument.NumItems),
			NumErased: int(metrics.Argument.NumErased),
			TotalSize: int(metrics.Argument.TotalSize),
		},
		Storage: ISStatus{
			NumItems:  int(metrics.Storage.NumItems),
			TotalSize: int(metrics.Storage.TotalSize),
		},
		Detector: DTStatus{
			IsEnabled:        metrics.Detector.IsEnabled.ToBool(),
			HasDebugger:      metrics.Detector.HasDebugger.ToBool(),
			HasMemoryScanner: metrics.Detector.HasMemoryScanner.ToBool(),
			InSandbox:        metrics.Detector.InSandbox.ToBool(),
			InVirtualMachine: metrics.Detector.InVirtualMachine.ToBool(),
			InEmulator:       metrics.Detector.InEmulator.ToBool(),
			IsAccelerated:    metrics.Detector.IsAccelerated.ToBool(),
			SafeRank:         metrics.Detector.SafeRank,
			NumDetectCalls:   metrics.Detector.NumDetectCalls,
		},
		Watchdog: WDStatus{
			IsEnabled: metrics.Watchdog.IsEnabled.ToBool(),
			NumKick:   metrics.Watchdog.NumKick,
			NumNormal: metrics.Watchdog.NumNormal,
			NumReset:  metrics.Watchdog.NumReset,
		},
		Sysmon: SMStatus{
			IsEnabled:  metrics.Sysmon.IsEnabled.ToBool(),
			NumNormal:  metrics.Sysmon.NumNormal,
			NumRecover: metrics.Sysmon.NumRecover,
			NumPanic:   metrics.Sysmon.NumPanic,
		},
		Shield: SDStatus{
			EntryPoint:  metrics.Shield.EntryPoint,
			BaseAddress: metrics.Shield.BaseAddress,
			Source:      shield.ConvertSource(metrics.Shield.Source),
		},
		Core: RTCore{
			Uptime:       metrics.Core.Uptime,
			InitElapsed:  metrics.Core.InitElapsed,
			SecurityMode: metrics.Core.SecurityMode.ToBool(),
			IsHealthy:    metrics.Core.IsHealthy.ToBool(),
		},
		Proc: RTProc{
			NumCalls:    metrics.Proc.NumCalls,
			NumRedirect: metrics.Proc.NumRedirect,
			NumFallback: metrics.Proc.NumFallback,
			NumRTMethod: metrics.Proc.NumRTMethod,
			NumRawProc:  metrics.Proc.NumRawProc,
		},
		Sleep: RTSleep{
			NumCalls:         metrics.Sleep.NumCalls,
			LastPreElapsed:   metrics.Sleep.LastPreElapsed,
			LastPostElapsed:  metrics.Sleep.LastPostElapsed,
			TotalPreElapsed:  metrics.Sleep.TotalPreElapsed,
			TotalPostElapsed: metrics.Sleep.TotalPostElapsed,
			MinPreElapsed:    metrics.Sleep.MinPreElapsed,
			MinPostElapsed:   metrics.Sleep.MinPostElapsed,
			MaxPreElapsed:    metrics.Sleep.MaxPreElapsed,
			MaxPostElapsed:   metrics.Sleep.MaxPostElapsed,
			AvgPreElapsed:    metrics.Sleep.AvgPreElapsed,
			AvgPostElapsed:   metrics.Sleep.AvgPostElapsed,
		},
	}
}
