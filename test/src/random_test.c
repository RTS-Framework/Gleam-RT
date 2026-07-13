#include <stdio.h>
#include "c_types.h"
#include "random.h"
#include "test.h"

static bool TestGenerateSeed();
static bool TestDeterminism();
static bool TestRandInt();
static bool TestRandInt8();
static bool TestRandInt16();
static bool TestRandInt32();
static bool TestRandInt64();
static bool TestRandUint();
static bool TestRandUint8();
static bool TestRandUint16();
static bool TestRandUint32();
static bool TestRandUint64();
static bool TestRandIntN();
static bool TestRandInt8N();
static bool TestRandInt16N();
static bool TestRandInt32N();
static bool TestRandInt64N();
static bool TestRandUintN();
static bool TestRandUint8N();
static bool TestRandUint16N();
static bool TestRandUint32N();
static bool TestRandUint64N();
static bool TestRandByte();
static bool TestRandBool();
static bool TestRandBOOL();
static bool TestRandBuffer();
static bool TestRandSequence();

bool TestRandom()
{
    typedef bool (*test_t)();
    test_t tests[] = 
    {
        { TestGenerateSeed },
        { TestDeterminism  },
        { TestRandInt      },
        { TestRandInt8     },
        { TestRandInt16    },
        { TestRandInt32    },
        { TestRandInt64    },
        { TestRandUint     },
        { TestRandUint8    },
        { TestRandUint16   },
        { TestRandUint32   },
        { TestRandUint64   },
        { TestRandIntN     },
        { TestRandInt8N    },
        { TestRandInt16N   },
        { TestRandInt32N   },
        { TestRandInt64N   },
        { TestRandUintN    },
        { TestRandUint8N   },
        { TestRandUint16N  },
        { TestRandUint32N  },
        { TestRandUint64N  },
        { TestRandByte     },
        { TestRandBool     },
        { TestRandBOOL     },
        { TestRandBuffer   },
        { TestRandSequence },
    };
    for (int i = 0; i < arrlen(tests); i++)
    {
        printf_s("--------------------------------\n");
        if (!tests[i]())
        {
            return false;
        }
        printf_s("--------------------------------\n\n");
    }
    return true;
}

static bool TestGenerateSeed()
{
    printf_s("======TestGenerateSeed begin=======\n");

    for (uint i = 0; i < 10; i++)
    {
        printf_s("seed: %llu\n", GenerateSeed());
    }

    printf_s("======TestGenerateSeed passed======\n\n");
    return true;
}

static bool TestDeterminism()
{
    printf_s("=======TestDeterminism begin=======\n");

    int v1 = RandInt(1234);
    int v2 = RandInt(1234);
    int v3 = RandInt(1235);
    if (v1 != v2)
    {
        printf_s("same seed but different value\n");
        return false;
    }
    if (v2 == v3)
    {
        printf_s("low entropy\n");
        return false;
    }

    printf_s("=======TestDeterminism passed======\n\n");
    return true;
}

static bool TestRandInt()
{
    printf_s("=========TestRandInt begin=========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("int: %lld\n", (uint64)RandInt(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandInt(last);
        printf_s("int: %lld\n", val);
        last += val;
    }

    printf_s("=========TestRandInt passed========\n\n");
    return true;
}

static bool TestRandInt8()
{
    printf_s("=========TestRandInt8 begin=========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("int8: %lld\n", (uint64)RandInt8(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandInt8(last);
        printf_s("int8: %lld\n", val);
        last += val;
    }

    printf_s("=========TestRandInt8 passed========\n\n");
    return true;
}

static bool TestRandInt16()
{
    printf_s("=========TestRandInt16 begin=========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("int16: %lld\n", (uint64)RandInt16(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandInt16(last);
        printf_s("int16: %lld\n", val);
        last += val;
    }

    printf_s("=========TestRandInt16 passed========\n\n");
    return true;
}

static bool TestRandInt32()
{
    printf_s("=========TestRandInt32 begin=========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("int32: %lld\n", (uint64)RandInt32(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandInt32(last);
        printf_s("int32: %lld\n", val);
        last += val;
    }

    printf_s("=========TestRandInt32 passed========\n\n");
    return true;
}

static bool TestRandInt64()
{
    printf_s("========TestRandInt64 begin========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("int64: %lld\n", (uint64)RandInt64(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandInt64(last);
        printf_s("int64: %lld\n", val);
        last += val;
    }

    printf_s("========TestRandInt64 passed=======\n\n");
    return true;
}

static bool TestRandUint()
{
    printf_s("=========TestRandUint begin========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("uint: %llu\n", (uint64)RandUint(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandUint(last);
        printf_s("uint: %llu\n", val);
        last += val;
    }

    printf_s("========TestRandUint passed========\n\n");
    return true;
}

static bool TestRandUint8()
{
    printf_s("=======TestRandUint8 begin========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("uint8: %llu\n", (uint64)RandUint8(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = RandUint8(last);
        printf_s("uint8: %llu\n", val);
        last += val;
    }

    printf_s("=======TestRandUint8 passed=======\n\n");
    return true;
}

static bool TestRandUint16()
{
    printf_s("=========TestRandUint16 begin========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("uint16: %llu\n", (uint64)RandUint16(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandUint16(last);
        printf_s("uint16: %llu\n", val);
        last += val;
    }

    printf_s("========TestRandUint16 passed========\n\n");
    return true;
}

static bool TestRandUint32()
{
    printf_s("=========TestRandUint32 begin========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("uint32: %llu\n", (uint64)RandUint32(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandUint32(last);
        printf_s("uint32: %llu\n", val);
        last += val;
    }

    printf_s("========TestRandUint32 passed========\n\n");
    return true;
}

static bool TestRandUint64()
{
    printf_s("=======TestRandUint64 begin========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("uint64: %llu\n", RandUint64(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = RandUint64(last);
        printf_s("uint64: %llu\n", val);
        last += val;
    }

    printf_s("=======TestRandUint64 passed=======\n\n");
    return true;
}

static bool TestRandIntN()
{
    printf_s("==========RandIntN begin===========\n");

    for (int i = 0; i < 5; i++)
    {
        uint64 seed = GenerateSeed();
        uint64 val  = (uint64)RandIntN(seed, 1024);
        if (val > 1024)
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        printf_s("int: %lld\n", val);
    }

    printf_s("==========RandIntN passed==========\n\n");
    return true;
}

static bool TestRandInt8N()
{
    printf_s("==========RandInt8N begin===========\n");

    for (int i = 0; i < 5; i++)
    {
        uint64 seed = GenerateSeed();
        uint64 val  = (uint64)RandInt8N(seed, 100);
        if (val > 100)
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        printf_s("int8: %lld\n", val);
    }

    printf_s("==========RandInt8N passed==========\n\n");
    return true;
}

static bool TestRandInt16N()
{
    printf_s("==========RandInt16N begin===========\n");

    for (int i = 0; i < 5; i++)
    {
        uint64 seed = GenerateSeed();
        uint64 val  = (uint64)RandInt16N(seed, 1024);
        if (val > 1024)
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        printf_s("int16: %lld\n", val);
    }

    printf_s("==========RandInt16N passed==========\n\n");
    return true;
}

static bool TestRandInt32N()
{
    printf_s("==========RandInt32N begin===========\n");

    for (int i = 0; i < 5; i++)
    {
        uint64 seed = GenerateSeed();
        uint64 val  = (uint64)RandInt32N(seed, 1024);
        if (val > 1024)
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        printf_s("int32: %lld\n", val);
    }

    printf_s("==========RandInt32N passed==========\n\n");
    return true;
}

static bool TestRandInt64N()
{
    printf_s("=========RandInt64N begin==========\n");

    for (int i = 0; i < 5; i++)
    {
        uint64 seed = GenerateSeed();
        uint64 val  = (uint64)RandInt64N(seed, 1024);
        if (val > 1024)
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        printf_s("int64: %lld\n", val);
    }

    printf_s("=========RandInt64N passed=========\n\n");
    return true;
}

static bool TestRandUintN()
{
    printf_s("=========RandUintN begin===========\n");

    for (int i = 0; i < 5; i++)
    {
        uint64 seed = GenerateSeed();
        uint64 val  = (uint64)RandUintN(seed, 1024);
        if (val > 1024)
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        printf_s("uint: %llu\n", val);
    }

    printf_s("=========RandUintN passed==========\n\n");
    return true;
}

static bool TestRandUint8N()
{
    printf_s("=========RandUint8N begin===========\n");

    for (int i = 0; i < 5; i++)
    {
        uint64 seed = GenerateSeed();
        uint64 val  = (uint64)RandUint8N(seed, 200);
        if (val > 200)
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        printf_s("uint8: %llu\n", val);
    }

    printf_s("=========RandUint8N passed==========\n\n");
    return true;
}

static bool TestRandUint16N()
{
    printf_s("=========RandUint16N begin===========\n");

    for (int i = 0; i < 5; i++)
    {
        uint64 seed = GenerateSeed();
        uint64 val  = (uint64)RandUint16N(seed, 1024);
        if (val > 1024)
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        printf_s("uint16: %llu\n", val);
    }

    printf_s("=========RandUint16N passed==========\n\n");
    return true;
}

static bool TestRandUint32N()
{
    printf_s("=========RandUint32N begin===========\n");

    for (int i = 0; i < 5; i++)
    {
        uint64 seed = GenerateSeed();
        uint64 val  = (uint64)RandUint32N(seed, 1024);
        if (val > 1024)
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        printf_s("uint32: %llu\n", val);
    }

    printf_s("=========RandUint32N passed==========\n\n");
    return true;
}

static bool TestRandUint64N()
{
    printf_s("========RandUint64N begin==========\n");

    for (int i = 0; i < 5; i++)
    {
        uint64 seed = GenerateSeed();
        uint64 val  = (uint64)RandUint64N(seed, 1024);
        if (val > 1024)
        {
            panic(PANIC_UNREACHABLE_CODE);
        }
        printf_s("uint64: %llu\n", val);
    }

    printf_s("========RandUint64N passed=========\n\n");
    return true;
}

static bool TestRandByte()
{
    printf_s("========TestRandByte begin=========\n");

    for (uint i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("byte: %d\n", RandByte(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (uint i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandByte(last);
        printf_s("byte: %lld\n", val);
        last += val;
    }

    printf_s("========TestRandByte passed========\n\n");
    return true;
}

static bool TestRandBool()
{
    printf_s("=========TestRandBool begin========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("bool: %d\n", RandBool(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandBool(last);
        printf_s("bool: %lld\n", val);
        last += last + val + 1;
    }

    printf_s("========TestRandBool passed========\n\n");
    return true;
}

static bool TestRandBOOL()
{
    printf_s("=========TestRandBOOL begin========\n");

    for (int i = 0; i < 3; i++)
    {
        uint64 seed = GenerateSeed();
        printf_s("bool: %d\n", RandBOOL(seed));
    }
    printf_s("\n");

    // iteration
    uint64 last = (uint64)(&TestRandBuffer);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandBOOL(last);
        printf_s("bool: %lld\n", val);
        last += last + val + 1;
    }

    printf_s("========TestRandBOOL passed========\n\n");
    return true;
}

static bool TestRandBuffer()
{
    printf_s("=======TestRandBuffer begin========\n");

    byte buf[16];
    RandBuffer(buf, arrlen(buf));

    printf_s("buf: ");
    for (int i = 0; i < arrlen(buf); i++)
    {
        printf_s("%d ", buf[i]);
    }
    printf_s("\n");

    printf_s("=======TestRandBuffer passed=======\n\n");
    return true;
}

static bool TestRandSequence()
{
    printf_s("========RandSequence begin==========\n");

    int seq[8];
    RandSequence(seq, arrlen(seq));

    printf_s("seq: [ ");
    for (int i = 0; i < arrlen(seq); i++)
    {
        printf_s("%d ", seq[i]);
    }
    printf_s("]\n");

    printf_s("========RandSequence passed=========\n\n");
    return true;
}
