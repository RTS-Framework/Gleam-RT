#include <stdio.h>
#include "c_types.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "lib_encode.h"
#include "test.h"

static bool TestLibEncode_Hex();
static bool TestLibEncode_Base64();

bool TestLibEncode()
{
    test_t tests[] =
    {
        { TestLibEncode_Hex    },
        { TestLibEncode_Base64 },
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

static bool TestLibEncode_Hex()
{
    byte data[] = { 0x12, 0x34, 0xAB, 0xCD };

    byte buf[9];
    mem_init(buf, sizeof(buf));

    uint len = Hex_Encode(data, sizeof(data), NULL);
    if (len != 8)
    {
        printf_s("invalid encode length\n");
        return false;
    }
    len = Hex_Encode(data, sizeof(data), buf);
    if (len != 8)
    {
        printf_s("invalid encode length\n");
        return false;
    }
    if (strcmp_a("1234ABCD", buf) != 0)
    {
        printf_s("invalid encode data\n");
        return false;
    }

    ANSI str = "1234AbCD";
    len = Hex_Decode(str, strlen_a(str), NULL);
    if (len != 4)
    {
        printf_s("invalid decode length\n");
        return false;
    }
    len = Hex_Decode(str, strlen_a(str), buf);
    if (len != 4)
    {
        printf_s("invalid decode length\n");
        return false;
    }
    if (!mem_equal(buf, data, sizeof(data)))
    {
        printf_s("invalid decode data\n");
        return false;
    }

    ANSI invalid = "invalid";
    if (Hex_Decode(invalid, strlen_a(invalid), buf) != -1)
    {
        printf_s("invalid decode length\n");
        return false;
    }

    printf_s("test Hex passed\n");
    return true;
}

static bool TestLibEncode_Base64()
{
    byte buf[64];
    mem_init(buf, sizeof(buf));

    // no padding
    byte data1[] = { 'M', 'a', 'n' };
    uint len = Base64_Encode(data1, sizeof(data1), NULL);
    if (len != 4)
    {
        printf_s("invalid encode length\n");
        return false;
    }
    len = Base64_Encode(data1, sizeof(data1), buf);
    if (len != 4)
    {
        printf_s("invalid encode length\n");
        return false;
    }
    if (strcmp_a("TWFu", buf) != 0)
    {
        printf_s("invalid encode data\n");
        return false;
    }

    ANSI str = "TWFu";
    len = Base64_Decode(str, strlen_a(str), NULL);
    if (len != 3)
    {
        printf_s("invalid decode length\n");
        return false;
    }
    len = Base64_Decode(str, strlen_a(str), buf);
    if (len != 3)
    {
        printf_s("invalid decode length\n");
        return false;
    }
    if (!mem_equal(buf, data1, sizeof(data1)))
    {
        printf_s("invalid decode data\n");
        return false;
    }

    // one '=' padding.
    byte data2[] = { 'M', 'a' };
    Base64_Encode(data2, sizeof(data2), buf);
    if (strcmp_a("TWE=", buf) != 0)
    {
        printf_s("invalid encode data\n");
        return false;
    }
    Base64_Decode("TWE=", 4, buf);
    if (!mem_equal(buf, data2, sizeof(data2)))
    {
        printf_s("invalid decode data\n");
        return false;
    }

    // two '=' padding.
    byte data3[] = { 'M' };
    Base64_Encode(data3, sizeof(data3), buf);
    if (strcmp_a("TQ==", buf) != 0)
    {
        printf_s("invalid encode data\n");
        return false;
    }
    Base64_Decode("TQ==", 4, buf);
    if (!mem_equal(buf, data3, sizeof(data3)))
    {
        printf_s("invalid decode data\n");
        return false;
    }
    
    // invalid input
    if (Base64_Decode("AA=A", 4, buf) != -1)
    {
        printf_s("invalid decode check\n");
        return false;
    }
    if (Base64_Decode("=AAA", 4, buf) != -1)
    {
        printf_s("invalid decode check\n");
        return false;
    }
    if (Base64_Decode("A==A", 4, buf) != -1)
    {
        printf_s("invalid decode check\n");
        return false;
    }
    if (Base64_Decode("TQ==AAAA", 8, buf) != -1)
    {
        printf_s("invalid decode check\n");
        return false;
    }
    if (Base64_Decode("????", 4, buf) != -1)
    {
        printf_s("invalid decode check\n");
        return false;
    }

    // round trip.
    byte data4[256];
    mem_init(data4, sizeof(data4));
    for (uint i = 0; i < sizeof(data4); i++)
    {
        data4[i] = (byte)i;
    }
    byte enc[512];
    byte dec[256];
    uint encLen = Base64_Encode(data4, sizeof(data4), enc);
    uint decLen = Base64_Decode(enc, encLen, dec);
    if (decLen != sizeof(data4))
    {
        printf_s("invalid round trip length\n");
        return false;
    }
    if (!mem_equal(data4, dec, sizeof(data4)))
    {
        printf_s("invalid round trip data\n");
        return false;
    }

    printf_s("test Base64 passed\n");
    return true;
}
