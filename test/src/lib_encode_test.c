#include <stdio.h>
#include "c_types.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "lib_encode.h"
#include "test.h"

static bool TestLibEncode_Hex();

bool TestLibEncode()
{
    test_t tests[] = 
    {
        { TestLibEncode_Hex },
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

    uint len = Hex_Encode(data, sizeof(data), buf);
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

    printf_s("test Hex passed\n");
    return true;
}
