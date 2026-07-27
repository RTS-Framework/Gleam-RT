#ifndef LIB_STRING_H
#define LIB_STRING_H

#include "c_types.h"

typedef byte*   ANSI;
typedef uint16* UTF16;

// strlen_a is used to calculate ANSI string length.
uint strlen_a(ANSI s);

// strlen_w is used to calculate UTF-16 string length.
uint strlen_w(UTF16 s);

// strcmp_a is used to compare two ANSI strings.
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int strcmp_a(ANSI a, ANSI b);

// strcmp_w is used to compare two UTF-16 strings.
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int strcmp_w(UTF16 a, UTF16 b);

// strncmp_a is used to compare two ANSI strings with length.
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int strncmp_a(ANSI a, ANSI b, uint n);

// strncmp_w is used to compare two UTF-16 strings with length.
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int strncmp_w(UTF16 a, UTF16 b, uint n);

// stricmp_a is used to compare two ANSI strings, it is case-insensitive.
// 
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int stricmp_a(ANSI a, ANSI b);

// stricmp_w is used to compare two UTF-16 strings, it is case-insensitive.
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int stricmp_w(UTF16 a, UTF16 b);

// strnicmp_a is used to compare two ANSI strings with length, it is case-insensitive.
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int strnicmp_a(ANSI a, ANSI b, uint n);

// strnicmp_w is used to compare two UTF-16 strings with length, it is case-insensitive.
// if a = b, return 0
// if a > b, return 1
// if a < b, return -1
int strnicmp_w(UTF16 a, UTF16 b, uint n);

// strcmp_a is used to compare two ANSI strings are equaled.
bool strequ_a(ANSI a, ANSI b);

// strcmp_w is used to compare two UTF-16 strings are equaled.
bool strequ_w(UTF16 a, UTF16 b);

// strcmp_a is used to compare two ANSI strings with length are equaled.
bool strnequ_a(ANSI a, ANSI b, uint n);

// strcmp_w is used to compare two UTF-16 strings with length are equaled.
bool strnequ_w(UTF16 a, UTF16 b, uint n);

// strcmp_a is used to compare two ANSI strings, it is case-insensitive.
bool striequ_a(ANSI a, ANSI b);

// strcmp_w is used to compare two UTF-16 strings, it is case-insensitive.
bool striequ_w(UTF16 a, UTF16 b);

// strcmp_a is used to compare two ANSI strings with length, it is case-insensitive.
bool strniequ_a(ANSI a, ANSI b, uint n);

// strcmp_w is used to compare two UTF-16 strings with length, it is case-insensitive.
bool strniequ_w(UTF16 a, UTF16 b, uint n);

// strcpy_a is used to copy source ANSI string to destination.
// return value is the number of copied characters, exclude the null.
uint strcpy_a(ANSI dst, ANSI src);

// strcpy_w is used to copy source UTF-16 string to destination.
// return value is the number of copied characters, exclude the null.
uint strcpy_w(UTF16 dst, UTF16 src);

// strncpy_a is used to copy source ANSI string to destination with length.
// it will stop after copying the null terminator.
// return value is the number of copied characters, exclude the null.
uint strncpy_a(ANSI dst, ANSI src, uint n);

// strncpy_w is used to copy source UTF-16 string to destination with length.
// it will stop after copying the null terminator.
// return value is the number of copied characters, exclude the null.
uint strncpy_w(UTF16 dst, UTF16 src, uint n);

#endif // LIB_STRING_H
