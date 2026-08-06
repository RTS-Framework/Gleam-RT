#ifndef COMPRESS_H
#define COMPRESS_H

#include "c_types.h"

// about search window size.
#define MINIMUM_WINDOW_SIZE 128
#define MAXIMUM_WINDOW_SIZE 4096
#define DEFAULT_WINDOW_SIZE 1024

// when chain length is MAXIMUM_CHAIN_LEN, it will use brute-force search
// for the best compression, but it is slowest, otherwise, it will use
// N-candidate hash chain for trade-off between speed and compression.
#define MINIMUM_CHAIN_LEN 1
#define MAXIMUM_CHAIN_LEN 16
#define DEFAULT_CHAIN_LEN 6

// hash table size: 2^12 = 4096 buckets for 3-byte hash.
#define HASH_BITS 12
#define HASH_SIZE (1 << HASH_BITS)

// Compress is used to compress data using LZSS with configurable parameters.
//
// Parameters:
//   window: sliding window size (128-4096, 0 for default 1024)
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
