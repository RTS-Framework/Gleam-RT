#ifndef WIN_TYPES_H
#define WIN_TYPES_H

#include "c_types.h"

typedef int32 BOOL;
typedef uint8 BOOLEAN;

typedef uint8  BYTE;
typedef uint16 WORD;
typedef uint32 DWORD;
typedef uint64 QWORD;

typedef int8   CHAR;
typedef int16  SHORT;
typedef int32  LONG;
typedef int64  LONGLONG;
typedef uint16 USHORT;
typedef uint32 ULONG;
typedef uint64 ULONGLONG;

typedef uint UINT;
typedef uint SIZE_T;
typedef uint ULONG_PTR;

typedef void* POINTER;
typedef void* HANDLE;

typedef void*   PVOID;
typedef uint8*  PSTR;
typedef uint16* PWSTR;
typedef HANDLE* PHANDLE;

typedef void*   LPVOID;
typedef uint8*  LPSTR;
typedef uint16* LPWSTR;
typedef HANDLE* LPHANDLE;

typedef const void*   PCVOID;
typedef const uint8*  PCSTR;
typedef const uint16* PCWSTR;

typedef const void*   LPCVOID;
typedef const uint8*  LPCSTR;
typedef const uint16* LPCWSTR;

#endif // WIN_TYPES_H
