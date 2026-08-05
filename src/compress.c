#include "c_types.h"
#include "lib_memory.h"
#include "lib_match.h"
#include "compress.h"

#define MIN_MATCH_LENGTH 3
#define MAX_MATCH_LENGTH 18

#define HASH_BITS 12
#define HASH_SIZE (1 << HASH_BITS)

static uint sHashCandidate(void* ht, byte* dst, byte* src, intx len, intx win);
static uint nHashCandidate(void* ht, byte* dst, byte* src, intx len, intx win, intx chain);
static uint bruteForce(byte* dst, byte* src, intx len, intx win);

static uint32 hash3(byte* b);
static intx   resolveCandidate(uint16 stored, intx dataPtr);

#pragma optimize("t", on)

uint Compress(void* ht, void* dst, void* src, uint len, uint window, uint chain)
{
    if (window > MAXIMUM_WINDOW_SIZE)
    {
        return (uint)(-1);
    }
    if (chain > MAXIMUM_CHAIN_LEN)
    {
        return (uint)(-1);
    }
    if (window == 0)
    {
        window = DEFAULT_WINDOW_SIZE;
    }
    if (chain == 0)
    {
        chain = DEFAULT_CHAIN_LEN;
    }
    byte* d = (byte*)dst;
    byte* s = (byte*)src;
    switch (chain)
    {
    case MINIMUM_CHAIN_LEN:
        return sHashCandidate(ht, d, s, len, window);
    case MAXIMUM_CHAIN_LEN:
        return bruteForce(d, s, len, window);
    default:
        return nHashCandidate(ht, d, s, len, window, chain);
    }
}

static uint sHashCandidate(void* ht, byte* dst, byte* src, intx len, intx win)
{
    // initialize hash table
    uint16* hashTable = (uint16*)ht;
    mem_init(hashTable, sizeof(uint16) * HASH_SIZE);

    byte flag = 0;
    intx flagPtr = 0;
    intx flagCtr = 0;

    intx dataPtr = 0;
    intx dstPtr  = 1;
    while (dataPtr < len)
    {
        intx rem = len - dataPtr;
        intx offset = 0;
        intx length = 0;
        if (rem >= MIN_MATCH_LENGTH)
        {
            uint32 h = hash3(src + dataPtr);
            uint16 stored = hashTable[h];
            if (stored != 0)
            {
                intx cdd = resolveCandidate(stored, dataPtr);
                intx dist = dataPtr - cdd;
                if (dist > 0 && dist <= win)
                {
                    intx maxLen = rem;
                    if (maxLen > MAX_MATCH_LENGTH)
                    {
                        maxLen = MAX_MATCH_LENGTH;
                    }
                    intx matchLen = 0;
                    while (matchLen < maxLen && src[cdd + matchLen] == src[dataPtr + matchLen])
                    {
                        matchLen++;
                    }
                    if (matchLen >= MIN_MATCH_LENGTH)
                    {
                        offset = dist - 1;
                        length = matchLen;
                    }
                }
            }
        }
        // set compress flag and write data
        if (length != 0)
        {
            flag |= 1;
            // 12 bit = offset, 4 bit = length
            // offset max is 4095, max length value is [0-15] + 3
            uint16 mark = (uint16)((offset << 4) | (length - MIN_MATCH_LENGTH));
            if (dst != NULL)
            {
                dst[dstPtr + 0] = (byte)(mark >> 0);
                dst[dstPtr + 1] = (byte)(mark >> 8);
            }
            dstPtr += 2;
        } else {
            if (dst != NULL)
            {
                dst[dstPtr] = src[dataPtr];
            }
            dstPtr++;
        }
        // update flag block
        if (flagCtr == 7)
        {
            if (dst != NULL)
            {
                dst[flagPtr] = flag;
            }
            // update pointer
            flagPtr = dstPtr;
            dstPtr++;
            // reset status
            flag = 0;
            flagCtr = 0;
        } else {
            flag <<= 1;
            flagCtr++;
        }
        // advance
        intx advance = 1;
        if (length != 0)
        {
            advance = length;
        }
        // update hash
        for (intx i = 0; i < advance && dataPtr + i + 2 < len; i++)
        {
            uint32 h = hash3(src + dataPtr + i);
            hashTable[h] = (uint16)(dataPtr + i + 1);
        }
        dataPtr += advance;
    }
    // process the final flag block
    if (flagCtr != 0)
    {
        flag <<= (byte)(7 - flagCtr);
        if (dst != NULL)
        {
            dst[flagPtr] = flag;
        }
    } else {
        dstPtr--; // rollback pointer
    }
    return (uint)dstPtr;
}

static uint nHashCandidate(void* ht, byte* dst, byte* src, intx len, intx win, intx chain)
{
    // initialize hash table
    uint16* hashTable = (uint16*)ht;
    mem_init(hashTable, sizeof(uint16) * HASH_SIZE * (uint)chain);

    byte flag = 0;
    intx flagPtr = 0;
    intx flagCtr = 0;

    intx dataPtr = 0;
    intx dstPtr  = 1;
    while (dataPtr < len)
    {
        intx rem = len - dataPtr;
        intx offset = 0;
        intx length = 0;
        if (rem >= MIN_MATCH_LENGTH)
        {
            uint32 h = hash3(src + dataPtr);
            intx base = (intx)h * chain;
            intx maxLen = rem;
            if (maxLen > MAX_MATCH_LENGTH)
            {
                maxLen = MAX_MATCH_LENGTH;
            }
            // search hash chain
            for (intx i = 0; i < chain; i++)
            {
                uint16 stored = hashTable[base + i];
                if (stored == 0)
                {
                    break;
                }
                intx cdd = resolveCandidate(stored, dataPtr);
                intx dist = dataPtr - cdd;
                if (dist <= 0 || dist > win)
                {
                    continue;
                }
                intx matchLen = 0;
                while (matchLen < maxLen && src[cdd + matchLen] == src[dataPtr + matchLen])
                {
                    matchLen++;
                }
                if (matchLen >= MIN_MATCH_LENGTH && matchLen > length)
                {
                    offset = dist - 1;
                    length = matchLen;
                    if (matchLen == maxLen)
                    {
                        break;
                    }
                }
            }
        }
        // set compress flag and write data
        if (length != 0)
        {
            flag |= 1;
            // 12 bit = offset, 4 bit = length
            // offset max is 4095, max length value is [0-15] + 3
            uint16 mark = (uint16)((offset << 4) | (length - MIN_MATCH_LENGTH));
            if (dst != NULL)
            {
                dst[dstPtr + 0] = (byte)(mark >> 0);
                dst[dstPtr + 1] = (byte)(mark >> 8);
            }
            dstPtr += 2;
        } else {
            if (dst != NULL)
            {
                dst[dstPtr] = src[dataPtr];
            }
            dstPtr++;
        }
        // update flag block
        if (flagCtr == 7)
        {
            if (dst != NULL)
            {
                dst[flagPtr] = flag;
            }
            // update pointer
            flagPtr = dstPtr;
            dstPtr++;
            // reset status
            flag = 0;
            flagCtr = 0;
        } else {
            flag <<= 1;
            flagCtr++;
        }
        // advance
        intx advance = 1;
        if (length != 0)
        {
            advance = length;
        }
        // update hash chain
        for (intx i = 0; i < advance && dataPtr + i + 2 < len; i++)
        {
            uint32 h = hash3(src + dataPtr + i);
            intx base = (intx)h * chain;
            for (intx j = chain - 1; j > 0; j--)
            {
                hashTable[base + j] = hashTable[base + j - 1];
            }
            hashTable[base] = (uint16)(dataPtr + i + 1);
        }
        dataPtr += advance;
    }
    // process the final flag block
    if (flagCtr != 0)
    {
        flag <<= (byte)(7 - flagCtr);
        if (dst != NULL)
        {
            dst[flagPtr] = flag;
        }
    } else {
        dstPtr--; // rollback pointer
    }
    return (uint)dstPtr;
}

static uint bruteForce(byte* dst, byte* src, intx len, intx win)
{
    byte flag = 0;
    intx flagPtr = 0;
    intx flagCtr = 0;

    intx dataPtr  = 0;
    intx dstPtr   = 1;
    intx winStart = 0;
    while (dataPtr < len)
    {
        intx rem = len - dataPtr;
        // search the same data in current window
        intx offset = 0;
        intx length = 0;
        if (rem >= MIN_MATCH_LENGTH)
        {
            intx winLen = dataPtr - winStart;
            intx maxLen = rem;
            if (maxLen > MAX_MATCH_LENGTH)
            {
                maxLen = MAX_MATCH_LENGTH;
            }
            // scan the window once, finding all 3-byte prefix matches
            // and extending each to find the best (longest then nearest) match
            intx bestOff = 0;
            intx bestLen = 0;
            intx pos = 0;
            while (pos <= winLen - MIN_MATCH_LENGTH)
            {
                byte* s   = src + winStart + pos;
                byte* sep = src + dataPtr;
                intx idx = MatchBytes(s, winLen - pos, sep, MIN_MATCH_LENGTH);
                if (idx == -1)
                {
                    break;
                }
                intx absPos = pos + idx;
                // extend the match
                intx matchLen = MIN_MATCH_LENGTH;
                while (matchLen < maxLen && absPos + matchLen < winLen &&
                    src[winStart + absPos + matchLen] == src[dataPtr + matchLen])
                {
                    matchLen++;
                }
                intx newOffset = winLen - absPos - 1;
                // prefer longer matches; equal length prefer nearer (smaller offset)
                if (matchLen > bestLen || (matchLen == bestLen && newOffset < bestOff))
                {
                    bestLen = matchLen;
                    bestOff = newOffset;
                    if (matchLen == maxLen)
                    {
                        break;
                    }
                }
                pos = absPos + 1;
            }
            if (bestLen >= MIN_MATCH_LENGTH)
            {
                offset = bestOff;
                length = bestLen;
            }
        }
        // set compress flag and write data
        if (length != 0)
        {
            flag |= 1;
            // 12 bit = offset, 4 bit = length
            // offset max is 4095, max length value is [0-15] + 3
            uint16 mark = (uint16)((offset << 4) | (length - MIN_MATCH_LENGTH));
            if (dst != NULL)
            {
                dst[dstPtr + 0] = (byte)(mark >> 0);
                dst[dstPtr + 1] = (byte)(mark >> 8);
            }
            dstPtr += 2;
        } else {
            if (dst != NULL)
            {
                dst[dstPtr] = src[dataPtr];
            }
            dstPtr++;
        }
        // update flag block
        if (flagCtr == 7)
        {
            if (dst != NULL)
            {
                dst[flagPtr] = flag;
            }
            // update pointer
            flagPtr = dstPtr;
            dstPtr++;
            // reset status
            flag = 0;
            flagCtr = 0;
        } else {
            flag <<= 1;
            flagCtr++;
        }
        // update data pointer
        if (length != 0)
        {
            dataPtr += length;
        } else {
            dataPtr++;
        }
        // update window
        intx start = dataPtr - win;
        if (start < 0)
        {
            start = 0;
        }
        winStart = start;
    }
    // process the final flag block
    if (flagCtr != 0)
    {
        flag <<= (byte)(7 - flagCtr);
        if (dst != NULL)
        {
            dst[flagPtr] = flag;
        }
    } else {
        dstPtr--; // rollback pointer
    }
    return (uint)dstPtr;
}

// hash3 computes a 12-bit hash of 3 consecutive bytes.
// reference Multiply-Shift Hash.
static uint32 hash3(byte* b)
{
    uint32 v = ((uint32)b[0] << 16) | ((uint32)b[1] << 8) | (uint32)b[2];
    return (v * 0x1E35A7BD) >> (32 - HASH_BITS);
}

// resolveCandidate reconstructs an absolute data position from a uint16 stored value.
// The stored value is (position + 1) as uint16, with 0 as the sentinel for "empty".
// Since the window is at most 4096 bytes, only one 64KB block can contain the
// candidate (-1 if same block, previous block otherwise).
static intx resolveCandidate(uint16 stored, intx dataPtr)
{
    intx lo = (intx)stored - 1;
    intx candidate = (dataPtr & ~0xFFFF) | lo;
    if (candidate > dataPtr)
    {
        candidate -= (intx)1 << 16;
    }
    return candidate;
}

uint Decompress(void* dst, void* src, uint len)
{
    byte* output = (byte*)dst;
    byte* input  = (byte*)src;
    intx dataLen = (intx)len;

    bool flag[8];
    mem_init(flag, sizeof(flag));
    intx flagIdx = 8;

    intx dstPtr = 0;
    intx srcPtr = 0;
    while (srcPtr < dataLen)
    {
        // check need read flag block
        if (flagIdx == 8)
        {
            byte b = input[srcPtr];
            flag[0] = (b & (1 << 7)) != 0;
            flag[1] = (b & (1 << 6)) != 0;
            flag[2] = (b & (1 << 5)) != 0;
            flag[3] = (b & (1 << 4)) != 0;
            flag[4] = (b & (1 << 3)) != 0;
            flag[5] = (b & (1 << 2)) != 0;
            flag[6] = (b & (1 << 1)) != 0;
            flag[7] = (b & (1 << 0)) != 0;
            srcPtr++;
            flagIdx = 0;
        }
        if (flag[flagIdx])
        {
            if (srcPtr + 1 >= dataLen)
            {
                return (uint)(-1); // truncated match reference
            }
            uint16 mark = *(uint16*)(input + srcPtr);
            intx offset = (intx)((mark >> 4) + 1);
            intx length = (intx)((mark & 0xF) + MIN_MATCH_LENGTH);
            intx start = dstPtr - offset;
            if (start < 0)
            {
                return (uint)(-1); // invalid match offset
            }
            if (dst != NULL)
            {
                mem_copy(output + dstPtr, output + start, length);
            }
            srcPtr += 2;
            dstPtr += length;
        } else {
            if (srcPtr >= dataLen)
            {
                return (uint)(-1); // truncated literal
            }
            if (dst != NULL)
            {
                output[dstPtr] = input[srcPtr];
            }
            srcPtr++;
            dstPtr++;
        }
        // update flag index
        flagIdx++;
    }
    return dstPtr;
}

#pragma optimize("t", off)
