#ifndef THREAD_H
#define THREAD_H

#include "c_types.h"
#include "dll_kernel32.h"

// CamouflageStartAddress is used to camouflage thread start address,
// it will return a random address at the text section of the image.
void* CamouflageStartAddress(HMODULE hModule, void* address);

#endif // THREAD_H
