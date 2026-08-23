#ifndef BUILD_H
#define BUILD_H

#define TEST_MODE

// ENABLE_DEBUGGER:    enable debugger module for test and debug
// ENABLE_FAST_SLEEP:  force adjust the RT_SleepHR duration to 1 ms
// DISABLE_PIC_MODE:   run unit tests under .text instance
// DISABLE_CAMOUFLAGE: disable all modules about camouflage for debug
// SMALL_CHUNK_SIZE:   adjust the read chunk size to smaller for test

// #define ENABLE_DEBUGGER
#define ENABLE_FAST_SLEEP
// #define DISABLE_PIC_MODE
// #define DISABLE_CAMOUFLAGE
#define SMALL_CHUNK_SIZE

// if enable debugger, must disable pic mode
#ifdef ENABLE_DEBUGGER
  #define DISABLE_PIC_MODE
#endif

#endif // BUILD_H
