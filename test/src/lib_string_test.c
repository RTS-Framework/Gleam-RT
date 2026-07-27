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
