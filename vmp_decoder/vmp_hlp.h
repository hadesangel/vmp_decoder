
#ifndef __vmp_hlp_h__
#define __vmp_hlp_h__

#include <Windows.h>

typedef struct vmp_hlp
{
    DWORD error;
    HANDLE hProcess;
    DWORD processId;
    bool init;
} vmp_hlp_t;

bool vmp_hlp_get_symbol(vmp_hlp_t *hlp);

#endif