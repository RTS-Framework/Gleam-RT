#ifndef LAYOUT_H
#define LAYOUT_H

// +--------------+--------------+-------------+-------------------+---------------+
// |    0-8191    |  8192-16383  | 16384-32767 |    32768-49151    |  49152-53247  |
// +--------------+--------------+-------------+-------------------+---------------+
// | runtime core | base modules |  submodule  | high-level module | suffix module |
// +--------------+--------------+-------------+-------------------+---------------+
//
// +---------------+
// |  53248-53503  |
// +---------------+
// | pointer table |
// +---------------+
//
// the main memory page store the data of all the core structures.
// pointer table is used to store module pointers.

#define MAIN_MEM_PAGE_SIZE (64 * 1024)

// ------------runtime core------------

#define LAYOUT_RUNTIME_STRUCT 1024
#define LAYOUT_RUNTIME_MODULE 4096

// ------------base module-------------

// Spoof Call
#define LAYOUT_SC_STRUCT 8192
#define LAYOUT_SC_MODULE 9000

// Indirect Syscall
#define LAYOUT_SS_STRUCT 10000
#define LAYOUT_SS_MODULE 11000

// Detector
#define LAYOUT_DT_STRUCT 12000
#define LAYOUT_DT_MODULE 13000

// -------------submodule--------------

// Library Tracker
#define LAYOUT_LT_STRUCT 16384
#define LAYOUT_LT_MODULE 17000

// Memory Tracker
#define LAYOUT_MT_STRUCT 18000
#define LAYOUT_MT_MODULE 19000

// Thread Tracker
#define LAYOUT_TT_STRUCT 21000
#define LAYOUT_TT_MODULE 22000

// Resource Tracker
#define LAYOUT_RT_STRUCT 23000
#define LAYOUT_RT_MODULE 24000

// Argument Store
#define LAYOUT_AS_STRUCT 26000
#define LAYOUT_AS_MODULE 26500

// In-memory Storage
#define LAYOUT_IS_STRUCT 27000
#define LAYOUT_IS_MODULE 27500

// ---------high-level module----------

// WinBase
#define LAYOUT_WB_STRUCT 32768
#define LAYOUT_WB_METHOD 34500

// WinFile
#define LAYOUT_WF_STRUCT 36000
#define LAYOUT_WF_METHOD 37000

// WinHTTP
#define LAYOUT_WH_STRUCT 38000
#define LAYOUT_WH_METHOD 39000

// WinCrypto
#define LAYOUT_WC_STRUCT 40000
#define LAYOUT_WC_METHOD 41000

// Watchdog
#define LAYOUT_WD_STRUCT 42000
#define LAYOUT_WD_METHOD 43000

// Sysmon
#define LAYOUT_SM_STRUCT 44000
#define LAYOUT_SM_METHOD 45000

// -----------suffix module------------

// Shield
#define LAYOUT_SD_STRUCT 49152
#define LAYOUT_SD_METHOD 50000

// -------------data page--------------

#define LAYOUT_POINTER_TABLE 53248

#endif // LAYOUT_H
