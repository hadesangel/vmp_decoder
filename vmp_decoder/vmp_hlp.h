

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __vmp_hlp_h__
#define __vmp_hlp_h__

#include <Windows.h>
#include "pe_loader.h"

typedef struct vmp_hlp
{
    DWORD error;
    HANDLE hProcess;
    DWORD processId;
    bool init;

    char *base_addr;        // pe_load base addr
    DWORD64 mod_base;       // symbol load addr
    struct pe_loader *pe_loader1;
} vmp_hlp_t;

struct vmp_hlp *vmp_hlp_create(struct pe_loader *loader, char *filename, HANDLE hand, char *base_addr);
int vmp_hlp_destroy(struct vmp_hlp *mod);

/*
@return         1       found   
                0       not found*/
int vmp_hlp_get_symbol(struct vmp_hlp *mod, DWORD64 rva, char *sym_name, int sym_buf_siz, DWORD64 *offset);
int vmp_hlp_get_symbol2(struct vmp_hlp *mod, DWORD64 fa, char *sym_name, int sym_buf_siz, DWORD64 *offset);

#endif


#ifdef __cplusplus
}
#endif