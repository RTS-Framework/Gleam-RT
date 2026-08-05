#ifndef COMPRESS_H
#define COMPRESS_H

#include "c_types.h"

#define DEFAULT_WINDOW_SIZE 1024
#define MAXIMUM_WINDOW_SIZE 4096

// when chain length is MAXIMUM_CHAIN_LEN, it will use brute-force search
// for the best compression, but it is slowest, otherwise, it will use
// N-candidate hash chain for trade-off between speed and compression.
#define MINIMUM_CHAIN_LEN 1
#define MAXIMUM_CHAIN_LEN 16

// default chain length for Compress:
// 1  = single hash candidate (fastest, worst compression)
// 6  = good balance
// 16 = brute-force (best compression, slowest)
#define DEFAULT_CHAIN_LEN 6

// Compress is used to compress data using LZSS with configurable parameters.
//
// Parameters:
//   window: sliding window size (0-4096, 0 for default 1024)
//   chain:  hash chain length for match search
//     1  = single hash candidate (fastest, worst compression)
//     N  = N-candidate hash chain (trade-off between speed and compression)
//     0  = 6-candidate hash chain
//     16 = brute-force (best compression, slowest)
//
// If return value is -1, window size or chain length is invalid.
// If dst is NULL, calculate the compressed length.
uint Compress(void* ht, void* dst, void* src, uint len, uint window, uint chain);

// Decompress is used to decompress data with LZSS.
// If return value is -1, the compressed data is invalid.
// If dst is NULL, calculate the raw data length.
uint Decompress(void* dst, void* src, uint len);

#endif // COMPRESS_H
