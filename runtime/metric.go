package gleamrt

import (
	"github.com/RTS-Framework/GRT-Develop/metric"
)

// Metrics contains status about runtime submodules.
type Metrics struct {
	Library  LTStatus `json:"library"`
	Memory   MTStatus `json:"memory"`
	Thread   TTStatus `json:"thread"`
	Resource RTStatus `json:"resource"`
	Detector DTStatus `json:"detector"`
	Watchdog WDStatus `json:"watchdog"`
	Sysmon   SMStatus `json:"sysmon"`
}

// LTStatus contains status about library tracker.
type LTStatus struct {
	NumModules    int64 `json:"num_modules"`
	NumProcedures int64 `json:"num_procedures"`
}

// MTStatus contains status about memory tracker.
type MTStatus struct {
	NumGlobals int64 `json:"num_globals"`
	NumLocals  int64 `json:"num_locals"`
	NumBlocks  int64 `json:"num_blocks"`
	NumRegions int64 `json:"num_regions"`
	NumPages   int64 `json:"num_pages"`
	NumHeaps   int64 `json:"num_heaps"`
}

// TTStatus contains status about thread tracker.
type TTStatus struct {
	NumThreads  int64 `json:"num_threads"`
	NumTLSIndex int64 `json:"num_tls_index"`
	NumSuspend  int64 `json:"num_suspend"`
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

// DTStatus contains status about detector.
type DTStatus struct {
	IsEnabled        bool  `json:"is_enabled"`
	HasDebugger      bool  `json:"has_debugger"`
	HasMemoryScanner bool  `json:"has_memory_scanner"`
	InSandbox        bool  `json:"in_sandbox"`
	InVirtualMachine bool  `json:"in_virtual_machine"`
	InEmulator       bool  `json:"in_emulator"`
	IsAccelerated    bool  `json:"is_accelerated"`
	SafeRank         int32 `json:"safe_rank"`
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

// ConvertRawMetrics is used to convert raw runtime metrics to go type.
func ConvertRawMetrics(metrics *metric.Metrics) *Metrics {
	return &Metrics{
		Library: LTStatus{
			NumModules:    metrics.Library.NumModules,
			NumProcedures: metrics.Library.NumProcedures,
		},
		Memory: MTStatus{
			NumGlobals: metrics.Memory.NumGlobals,
			NumLocals:  metrics.Memory.NumLocals,
			NumBlocks:  metrics.Memory.NumBlocks,
			NumRegions: metrics.Memory.NumRegions,
			NumPages:   metrics.Memory.NumPages,
			NumHeaps:   metrics.Memory.NumHeaps,
		},
		Thread: TTStatus{
			NumThreads:  metrics.Thread.NumThreads,
			NumTLSIndex: metrics.Thread.NumTLSIndex,
			NumSuspend:  metrics.Thread.NumSuspend,
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
		Detector: DTStatus{
			IsEnabled:        metrics.Detector.IsEnabled.ToBool(),
			HasDebugger:      metrics.Detector.HasDebugger.ToBool(),
			HasMemoryScanner: metrics.Detector.HasMemoryScanner.ToBool(),
			InSandbox:        metrics.Detector.InSandbox.ToBool(),
			InVirtualMachine: metrics.Detector.InVirtualMachine.ToBool(),
			InEmulator:       metrics.Detector.InEmulator.ToBool(),
			IsAccelerated:    metrics.Detector.IsAccelerated.ToBool(),
			SafeRank:         metrics.Detector.SafeRank,
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
	}
}
