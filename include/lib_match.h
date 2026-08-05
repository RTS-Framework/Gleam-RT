#ifndef LIB_MATCH_H
#define LIB_MATCH_H

#include "c_types.h"

// MatchByte is used to search the same byte that use brute force.
intx MatchByte(byte* s, intx ns, byte b);

// MatchBytes is used to search the same sub bytes with different strategy.
intx MatchBytes(byte* s, intx ns, byte* sep, intx nsep);

#endif // LIB_MATCH_H
