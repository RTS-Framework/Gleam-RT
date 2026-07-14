#include "c_types.h"
#include "win_structs.h"
#include "errno.h"

__declspec(noinline)
void SetLastErrno(errno err)
{
#ifdef _WIN64
    TEB* teb = (TEB*)__readgsqword(0x30);
#elif _WIN32
    TEB* teb = (TEB*)__readfsdword(0x18);
#endif
    teb->LastErrorValue = err;
}

__declspec(noinline)
errno GetLastErrno()
{
#ifdef _WIN64
    TEB* teb = (TEB*)__readgsqword(0x30);
#elif _WIN32
    TEB* teb = (TEB*)__readfsdword(0x18);
#endif
    return teb->LastErrorValue;
}
