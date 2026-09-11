#include <stdio.h>
#include "c_types.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "test.h"

static bool TestStrlen_a();
static bool TestStrlen_w();
static bool TestStrcmp_a();
static bool TestStrcmp_w();
static bool TestStrncmp_a();
static bool TestStrncmp_w();
static bool TestStricmp_a();
static bool TestStricmp_w();
static bool TestStrnicmp_a();
static bool TestStrnicmp_w();
static bool TestStrcpy_a();
static bool TestStrcpy_w();
static bool TestStrncpy_a();
static bool TestStrncpy_w();
static bool TestStrequ_a();
static bool TestStrequ_w();
static bool TestStrnequ_a();
static bool TestStrnequ_w();
static bool TestStriequ_a();
static bool TestStriequ_w();
static bool TestStrniequ_a();
static bool TestStrniequ_w();
static bool TestStr2uint_a();
static bool TestStr2uint_w();

bool TestLibString()
{
    test_t tests[] =
    {
        { TestStrlen_a   },
        { TestStrlen_w   },
        { TestStrcmp_a   },
        { TestStrcmp_w   },
        { TestStrncmp_a  },
        { TestStrncmp_w  },
        { TestStricmp_a  },
        { TestStricmp_w  },
        { TestStrnicmp_a },
        { TestStrnicmp_w },
        { TestStrcpy_a   },
        { TestStrcpy_w   },
        { TestStrncpy_a  },
        { TestStrncpy_w  },
        { TestStrequ_a   },
        { TestStrequ_w   },
        { TestStrnequ_a  },
        { TestStrnequ_w  },
        { TestStriequ_a  },
        { TestStriequ_w  },
        { TestStrniequ_a },
        { TestStrniequ_w },
        { TestStr2uint_a },
        { TestStr2uint_w },
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

static bool TestStrlen_a()
{
    ANSI str = "ansi";

    if (strlen_a(str) != 4)
    {
        printf_s("strlen_a return incorrect length\n");
        return false;
    }
    printf_s("test strlen_a passed\n");

    str = "";
    if (strlen_a(str) != 0)
    {
        printf_s("strlen_a return incorrect length\n");
        return false;
    }
    printf_s("test strlen_a with null passed\n");
    return true;
}

static bool TestStrlen_w()
{
    UTF16 str = L"utf16";

    if (strlen_w(str) != 5)
    {
        printf_s("strlen_w return incorrect length\n");
        return false;
    }
    printf_s("test strlen_w passed\n");

    str = L"";
    if (strlen_w(str) != 0)
    {
        printf_s("strlen_w return incorrect length\n");
        return false;
    }
    printf_s("test strlen_w with null passed\n");
    return true;
}

static bool TestStrcmp_a()
{
    ANSI s0 = "abc";
    ANSI s1 = "abc";
    if (strcmp_a(s0, s1) != 0)
    {
        printf_s("strcmp_a return incorrect value\n");
        return false;
    }
    printf_s("test strcmp_a with s0=s1 passed\n");

    s0 = "acc";
    s1 = "abc";
    if (strcmp_a(s0, s1) != 1)
    {
        printf_s("strcmp_a return incorrect value\n");
        return false;
    }
    printf_s("test strcmp_a with s0>s1 passed\n");

    s0 = "aac";
    s1 = "abc";
    if (strcmp_a(s0, s1) != -1)
    {
        printf_s("strcmp_a return incorrect value\n");
        return false;
    }
    printf_s("test strcmp_a with s0<s1 passed\n");
    return true;
}

static bool TestStrcmp_w()
{
    UTF16 s0 = L"abc";
    UTF16 s1 = L"abc";
    if (strcmp_w(s0, s1) != 0)
    {
        printf_s("strcmp_w return incorrect value\n");
        return false;
    }
    printf_s("test strcmp_w with s0=s1 passed\n");

    s0 = L"acc";
    s1 = L"abc";
    if (strcmp_w(s0, s1) != 1)
    {
        printf_s("strcmp_w return incorrect value\n");
        return false;
    }
    printf_s("test strcmp_w with s0>s1 passed\n");

    s0 = L"aac";
    s1 = L"abc";
    if (strcmp_w(s0, s1) != -1)
    {
        printf_s("strcmp_w return incorrect value\n");
        return false;
    }
    printf_s("test strcmp_w with s0<s1 passed\n");
    return true;
}

static bool TestStrncmp_a()
{
    ANSI s0 = "abc";
    ANSI s1 = "abc";
    if (strncmp_a(s0, s1, 2) != 0)
    {
        printf_s("strncmp_a return incorrect value\n");
        return false;
    }
    printf_s("test strncmp_a with s0=s1 passed\n");

    s0 = "acc";
    s1 = "abc";
    if (strncmp_a(s0, s1, 2) != 1)
    {
        printf_s("strncmp_a return incorrect value\n");
        return false;
    }
    printf_s("test strncmp_a with s0>s1 passed\n");

    s0 = "aac";
    s1 = "abc";
    if (strncmp_a(s0, s1, 2) != -1)
    {
        printf_s("strncmp_a return incorrect value\n");
        return false;
    }
    printf_s("test strncmp_a with s0<s1 passed\n");
    return true;
}

static bool TestStrncmp_w()
{
    UTF16 s0 = L"abc";
    UTF16 s1 = L"abc";
    if (strncmp_w(s0, s1, 2) != 0)
    {
        printf_s("strncmp_w return incorrect value\n");
        return false;
    }
    printf_s("test strncmp_w with s0=s1 passed\n");

    s0 = L"acc";
    s1 = L"abc";
    if (strncmp_w(s0, s1, 2) != 1)
    {
        printf_s("strncmp_w return incorrect value\n");
        return false;
    }
    printf_s("test strncmp_w with s0>s1 passed\n");

    s0 = L"aac";
    s1 = L"abc";
    if (strncmp_w(s0, s1, 2) != -1)
    {
        printf_s("strncmp_w return incorrect value\n");
        return false;
    }
    printf_s("test strncmp_w with s0<s1 passed\n");
    return true;
}

static bool TestStricmp_a()
{
    ANSI s0 = "aBc";
    ANSI s1 = "AbC";
    if (stricmp_a(s0, s1) != 0)
    {
        printf_s("stricmp_a return incorrect value\n");
        return false;
    }
    printf_s("test stricmp_a with s0=s1 passed\n");

    s0 = "aCc";
    s1 = "abc";
    if (stricmp_a(s0, s1) != 1)
    {
        printf_s("stricmp_a return incorrect value\n");
        return false;
    }
    printf_s("test stricmp_a with s0>s1 passed\n");

    s0 = "aac";
    s1 = "aBc";
    if (stricmp_a(s0, s1) != -1)
    {
        printf_s("stricmp_a return incorrect value\n");
        return false;
    }
    printf_s("test stricmp_a with s0<s1 passed\n");
    return true;
}

static bool TestStricmp_w()
{
    UTF16 s0 = L"aBc";
    UTF16 s1 = L"AbC";
    if (stricmp_w(s0, s1) != 0)
    {
        printf_s("stricmp_w return incorrect value\n");
        return false;
    }
    printf_s("test stricmp_w with s0=s1 passed\n");

    s0 = L"aCc";
    s1 = L"abc";
    if (stricmp_w(s0, s1) != 1)
    {
        printf_s("stricmp_w return incorrect value\n");
        return false;
    }
    printf_s("test stricmp_w with s0>s1 passed\n");

    s0 = L"aac";
    s1 = L"aBc";
    if (stricmp_w(s0, s1) != -1)
    {
        printf_s("stricmp_w return incorrect value\n");
        return false;
    }
    printf_s("test stricmp_w with s0<s1 passed\n");
    return true;
}

static bool TestStrnicmp_a()
{
    ANSI s0 = "aBc";
    ANSI s1 = "AbC";
    if (strnicmp_a(s0, s1, 2) != 0)
    {
        printf_s("strnicmp_a return incorrect value\n");
        return false;
    }
    printf_s("test strnicmp_a with s0=s1 passed\n");

    s0 = "aCc";
    s1 = "abc";
    if (strnicmp_a(s0, s1, 2) != 1)
    {
        printf_s("strnicmp_a return incorrect value\n");
        return false;
    }
    printf_s("test strnicmp_a with s0>s1 passed\n");

    s0 = "aac";
    s1 = "aBc";
    if (strnicmp_a(s0, s1, 2) != -1)
    {
        printf_s("strnicmp_a return incorrect value\n");
        return false;
    }
    printf_s("test strnicmp_a with s0<s1 passed\n");
    return true;
}

static bool TestStrnicmp_w()
{
    UTF16 s0 = L"aBc";
    UTF16 s1 = L"AbC";
    if (strnicmp_w(s0, s1, 2) != 0)
    {
        printf_s("strnicmp_w return incorrect value\n");
        return false;
    }
    printf_s("test strnicmp_w with s0=s1 passed\n");

    s0 = L"aCc";
    s1 = L"abc";
    if (strnicmp_w(s0, s1, 2) != 1)
    {
        printf_s("strnicmp_w return incorrect value\n");
        return false;
    }
    printf_s("test strnicmp_w with s0>s1 passed\n");

    s0 = L"aac";
    s1 = L"aBc";
    if (strnicmp_w(s0, s1, 2) != -1)
    {
        printf_s("strnicmp_w return incorrect value\n");
        return false;
    }
    printf_s("test strnicmp_w with s0<s1 passed\n");
    return true;
}

static bool TestStrcpy_a()
{
    ANSI s = "abc";
    byte c[8];
    mem_init(c, sizeof(c));

    if (strcpy_a(c, s) != 3)
    {
        printf_s("strcpy_a return incorrect value\n");
        return false;
    }

    printf_s("test strcpy_a passed\n");
    return true;
}

static bool TestStrcpy_w()
{
    UTF16 s = L"abc";
    uint16 c[8];
    mem_init(c, sizeof(c));

    if (strcpy_w(c, s) != 3)
    {
        printf_s("strcpy_w return incorrect value\n");
        return false;
    }

    printf_s("test strcpy_w passed\n");
    return true;
}

static bool TestStrncpy_a()
{
    ANSI s = "abc";
    byte c[8];
    mem_init(c, sizeof(c));

    if (strncpy_a(c, s, 3) != 3)
    {
        printf_s("strncpy_a return incorrect value\n");
        return false;
    }

    if (strncpy_a(c, s, 2) != 2)
    {
        printf_s("strncpy_a return incorrect value\n");
        return false;
    }

    if (strncpy_a(c, s, 4) != 3)
    {
        printf_s("strncpy_a return incorrect value\n");
        return false;
    }

    printf_s("test strncpy_a passed\n");
    return true;
}

static bool TestStrncpy_w()
{
    UTF16 s = L"abc";
    uint16 c[8];
    mem_init(c, sizeof(c));

    if (strncpy_w(c, s, 3) != 3)
    {
        printf_s("strncpy_w return incorrect value\n");
        return false;
    }

    if (strncpy_w(c, s, 2) != 2)
    {
        printf_s("strncpy_w return incorrect value\n");
        return false;
    }

    if (strncpy_w(c, s, 4) != 3)
    {
        printf_s("strncpy_w return incorrect value\n");
        return false;
    }

    printf_s("test strncpy_w passed\n");
    return true;
}

static bool TestStrequ_a()
{
    ANSI s0 = "abc";
    ANSI s1 = "abc";
    if (!strequ_a(s0, s1))
    {
        printf_s("strequ_a return incorrect value with equal strings\n");
        return false;
    }
    printf_s("test strequ_a with equal strings passed\n");

    s0 = "abc";
    s1 = "abd";
    if (strequ_a(s0, s1))
    {
        printf_s("strequ_a return incorrect value with different strings\n");
        return false;
    }
    printf_s("test strequ_a with different strings passed\n");

    s0 = "abc";
    s1 = "ab";
    if (strequ_a(s0, s1))
    {
        printf_s("strequ_a return incorrect value with different length strings\n");
        return false;
    }
    printf_s("test strequ_a with different length strings passed\n");
    return true;
}

static bool TestStrequ_w()
{
    UTF16 s0 = L"abc";
    UTF16 s1 = L"abc";
    if (!strequ_w(s0, s1))
    {
        printf_s("strequ_w return incorrect value with equal strings\n");
        return false;
    }
    printf_s("test strequ_w with equal strings passed\n");

    s0 = L"abc";
    s1 = L"abd";
    if (strequ_w(s0, s1))
    {
        printf_s("strequ_w return incorrect value with different strings\n");
        return false;
    }
    printf_s("test strequ_w with different strings passed\n");

    s0 = L"abc";
    s1 = L"ab";
    if (strequ_w(s0, s1))
    {
        printf_s("strequ_w return incorrect value with different length strings\n");
        return false;
    }
    printf_s("test strequ_w with different length strings passed\n");
    return true;
}

static bool TestStrnequ_a()
{
    ANSI s0 = "abc";
    ANSI s1 = "abc";
    if (!strnequ_a(s0, s1, 3))
    {
        printf_s("strnequ_a return incorrect value with equal strings\n");
        return false;
    }
    printf_s("test strnequ_a with equal strings passed\n");

    s0 = "abc";
    s1 = "abd";
    if (!strnequ_a(s0, s1, 2))
    {
        printf_s("strnequ_a return incorrect value with equal prefix\n");
        return false;
    }
    printf_s("test strnequ_a with equal prefix passed\n");

    s0 = "abc";
    s1 = "abd";
    if (strnequ_a(s0, s1, 3))
    {
        printf_s("strnequ_a return incorrect value with different strings\n");
        return false;
    }
    printf_s("test strnequ_a with different strings passed\n");
    return true;
}

static bool TestStrnequ_w()
{
    UTF16 s0 = L"abc";
    UTF16 s1 = L"abc";
    if (!strnequ_w(s0, s1, 3))
    {
        printf_s("strnequ_w return incorrect value with equal strings\n");
        return false;
    }
    printf_s("test strnequ_w with equal strings passed\n");

    s0 = L"abc";
    s1 = L"abd";
    if (!strnequ_w(s0, s1, 2))
    {
        printf_s("strnequ_w return incorrect value with equal prefix\n");
        return false;
    }
    printf_s("test strnequ_w with equal prefix passed\n");

    s0 = L"abc";
    s1 = L"abd";
    if (strnequ_w(s0, s1, 3))
    {
        printf_s("strnequ_w return incorrect value with different strings\n");
        return false;
    }
    printf_s("test strnequ_w with different strings passed\n");
    return true;
}

static bool TestStriequ_a()
{
    ANSI s0 = "aBc";
    ANSI s1 = "AbC";
    if (!striequ_a(s0, s1))
    {
        printf_s("striequ_a return incorrect value with equal strings\n");
        return false;
    }
    printf_s("test striequ_a with equal strings passed\n");

    s0 = "abc";
    s1 = "abd";
    if (striequ_a(s0, s1))
    {
        printf_s("striequ_a return incorrect value with different strings\n");
        return false;
    }
    printf_s("test striequ_a with different strings passed\n");

    s0 = "abc";
    s1 = "ab";
    if (striequ_a(s0, s1))
    {
        printf_s("striequ_a return incorrect value with different length strings\n");
        return false;
    }
    printf_s("test striequ_a with different length strings passed\n");
    return true;
}

static bool TestStriequ_w()
{
    UTF16 s0 = L"aBc";
    UTF16 s1 = L"AbC";
    if (!striequ_w(s0, s1))
    {
        printf_s("striequ_w return incorrect value with equal strings\n");
        return false;
    }
    printf_s("test striequ_w with equal strings passed\n");

    s0 = L"abc";
    s1 = L"abd";
    if (striequ_w(s0, s1))
    {
        printf_s("striequ_w return incorrect value with different strings\n");
        return false;
    }
    printf_s("test striequ_w with different strings passed\n");

    s0 = L"abc";
    s1 = L"ab";
    if (striequ_w(s0, s1))
    {
        printf_s("striequ_w return incorrect value with different length strings\n");
        return false;
    }
    printf_s("test striequ_w with different length strings passed\n");
    return true;
}

static bool TestStrniequ_a()
{
    ANSI s0 = "aBc";
    ANSI s1 = "AbC";
    if (!strniequ_a(s0, s1, 3))
    {
        printf_s("strniequ_a return incorrect value with equal strings\n");
        return false;
    }
    printf_s("test strniequ_a with equal strings passed\n");

    s0 = "aBc";
    s1 = "Abd";
    if (!strniequ_a(s0, s1, 2))
    {
        printf_s("strniequ_a return incorrect value with equal prefix\n");
        return false;
    }
    printf_s("test strniequ_a with equal prefix passed\n");

    s0 = "aBc";
    s1 = "Abd";
    if (strniequ_a(s0, s1, 3))
    {
        printf_s("strniequ_a return incorrect value with different strings\n");
        return false;
    }
    printf_s("test strniequ_a with different strings passed\n");
    return true;
}

static bool TestStrniequ_w()
{
    UTF16 s0 = L"aBc";
    UTF16 s1 = L"AbC";
    if (!strniequ_w(s0, s1, 3))
    {
        printf_s("strniequ_w return incorrect value with equal strings\n");
        return false;
    }
    printf_s("test strniequ_w with equal strings passed\n");

    s0 = L"aBc";
    s1 = L"Abd";
    if (!strniequ_w(s0, s1, 2))
    {
        printf_s("strniequ_w return incorrect value with equal prefix\n");
        return false;
    }
    printf_s("test strniequ_w with equal prefix passed\n");

    s0 = L"aBc";
    s1 = L"Abd";
    if (strniequ_w(s0, s1, 3))
    {
        printf_s("strniequ_w return incorrect value with different strings\n");
        return false;
    }
    printf_s("test strniequ_w with different strings passed\n");
    return true;
}

static bool TestStr2uint_a()
{
    uint num = 0;
    ANSI str = "123";

    if (!str2uint_a(str, &num) || num != 123)
    {
        printf_s("str2uint_a convert incorrect value\n");
        return false;
    }

    str = "0";
    if (!str2uint_a(str, &num) || num != 0)
    {
        printf_s("str2uint_a convert incorrect value with zero\n");
        return false;
    }

    str = "007";
    if (!str2uint_a(str, &num) || num != 7)
    {
        printf_s("str2uint_a convert incorrect value with leading zeros\n");
        return false;
    }
    printf_s("test str2uint_a passed\n");

    // the ordinal only contains digits, other characters must be rejected
    str = "";
    if (str2uint_a(str, &num))
    {
        printf_s("str2uint_a accept empty string\n");
        return false;
    }

    str = "#1";
    if (str2uint_a(str, &num))
    {
        printf_s("str2uint_a accept invalid first character\n");
        return false;
    }

    str = "12x";
    num = 0xFFFFFFFF;
    if (str2uint_a(str, &num) || num != 0xFFFFFFFF)
    {
        printf_s("str2uint_a accept invalid character\n");
        return false;
    }
    printf_s("test str2uint_a with invalid string passed\n");

#ifdef _WIN64
    ANSI maxStr  = "18446744073709551615"; // UINT64_MAX
    ANSI overStr = "18446744073709551616"; // UINT64_MAX + 1
#elif _WIN32
    ANSI maxStr  = "4294967295";           // UINT32_MAX
    ANSI overStr = "4294967296";           // UINT32_MAX + 1
#endif
    if (!str2uint_a(maxStr, &num) || num != (uint)-1)
    {
        printf_s("str2uint_a convert incorrect value with uint max\n");
        return false;
    }

    if (str2uint_a(overStr, &num))
    {
        printf_s("str2uint_a accept overflow value\n");
        return false;
    }
    printf_s("test str2uint_a with uint max passed\n");

    if (str2uint_a(NULL, &num) || str2uint_a(str, NULL))
    {
        printf_s("str2uint_a accept null argument\n");
        return false;
    }
    printf_s("test str2uint_a with null argument passed\n");
    return true;
}

static bool TestStr2uint_w()
{
    uint num = 0;
    UTF16 str = L"123";

    if (!str2uint_w(str, &num) || num != 123)
    {
        printf_s("str2uint_w convert incorrect value\n");
        return false;
    }

    str = L"0";
    if (!str2uint_w(str, &num) || num != 0)
    {
        printf_s("str2uint_w convert incorrect value with zero\n");
        return false;
    }

    str = L"007";
    if (!str2uint_w(str, &num) || num != 7)
    {
        printf_s("str2uint_w convert incorrect value with leading zeros\n");
        return false;
    }
    printf_s("test str2uint_w passed\n");

    // the ordinal only contains ASCII digits, other characters must be rejected
    str = L"";
    if (str2uint_w(str, &num))
    {
        printf_s("str2uint_w accept empty string\n");
        return false;
    }

    str = L"#1";
    if (str2uint_w(str, &num))
    {
        printf_s("str2uint_w accept invalid first character\n");
        return false;
    }

    str = L"12x";
    num = 0xFFFFFFFF;
    if (str2uint_w(str, &num) || num != 0xFFFFFFFF)
    {
        printf_s("str2uint_w accept invalid character\n");
        return false;
    }

    str = L"1\xFF11"; // U+FF11, full width digit one
    if (str2uint_w(str, &num))
    {
        printf_s("str2uint_w accept full width digit\n");
        return false;
    }
    printf_s("test str2uint_w with invalid string passed\n");

#ifdef _WIN64
    UTF16 maxStr  = L"18446744073709551615"; // UINT64_MAX
    UTF16 overStr = L"18446744073709551616"; // UINT64_MAX + 1
#elif _WIN32
    UTF16 maxStr  = L"4294967295";           // UINT32_MAX
    UTF16 overStr = L"4294967296";           // UINT32_MAX + 1
#endif
    if (!str2uint_w(maxStr, &num) || num != (uint)-1)
    {
        printf_s("str2uint_w convert incorrect value with uint max\n");
        return false;
    }

    if (str2uint_w(overStr, &num))
    {
        printf_s("str2uint_w accept overflow value\n");
        return false;
    }
    printf_s("test str2uint_w with uint max passed\n");

    if (str2uint_w(NULL, &num) || str2uint_w(str, NULL))
    {
        printf_s("str2uint_w accept null argument\n");
        return false;
    }
    printf_s("test str2uint_w with null argument passed\n");
    return true;
}
