
#ifdef __cplusplus
extern "C" {
#endif

#include <Windows.h>
#include <DbgHelp.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vmp_hlp.h"
#include "pe_loader.h"

    BOOL CALLBACK vmp_hlp_sym_enum_callback(PSYMBOL_INFO sym_info, ULONG sym_size, PVOID user_ctx)
    {
        //printf("function :%I64x : %s\r\n",  sym_info->Address, sym_info->Name);
        return TRUE;
    }

    struct vmp_hlp *vmp_hlp_create(struct pe_loader *loader, char *filename, HANDLE hand, char *base_addr)
    {
        struct vmp_hlp *mod = (struct vmp_hlp *)calloc(1, sizeof (mod[0]));
        DWORD options;
        int ret;

        if (!mod)
        {
            printf("vmp_hlp_create() failed when calloc()\n");
            return NULL;
        }

        mod->base_addr = base_addr;
        mod->pe_loader1 = loader;

        options = SymGetOptions();
        
        // SYMOPT_DEBUG option asks DbgHelp to print additional troubleshooting
        // messages to debug output - use the debugger's Debug Output window 
        // to view the message
        options |= SYMOPT_DEBUG;

        SymSetOptions(options);

        ret = SymInitialize(GetCurrentProcess(), 
            NULL,  // No use-defined serach path -> use default
            FALSE);

        if (!ret)
        {
            printf("vmp_hlp_create() failed when SymInitialize()");
            return NULL;
        }

        mod->mod_base = SymLoadModuleEx(GetCurrentProcess(),
            hand, NULL, NULL, (DWORD64)0, 0, NULL, 0);

        if (0 == mod->mod_base)
        {
            printf("vmp_hlp_create() failed when SymLoadModuleEx()\n");
            return NULL;
        }
        //printf("mod base = 0x%I64X\n", mod->mod_base);

        if (!SymEnumSymbols(GetCurrentProcess(),
            mod->mod_base, 0, (PSYM_ENUMERATESYMBOLS_CALLBACK)vmp_hlp_sym_enum_callback, NULL))
        {
            printf("vmp_hlp_create() failed when SymEnumSymbols()\n");
            return NULL;
        }

        return mod;
    }

    int vmp_hlp_destroy(struct vmp_hlp *mod)
    {
        SymCleanup(GetCurrentProcess());

        free(mod);

        return 0;
    }

    int vmp_hlp_get_symbol(struct vmp_hlp *mod, DWORD64 rva, char *sym_name, int sym_buf_siz, DWORD64 *offset)
    {
        DWORD64 displacement;
        PSYMBOL_INFO pinfo;
        char buf[512];
        pinfo = (PSYMBOL_INFO)buf;

        if (!mod)
            return 0;

        pinfo->SizeOfStruct = sizeof(SYMBOL_INFO);
        pinfo->MaxNameLen = sym_buf_siz;

        //printf("address = 0x%I64x. %s:%d\n", rva + mod->mod_base, __FILE__, __LINE__);
        if (SymFromAddr(GetCurrentProcess(), rva + mod->mod_base, &displacement, pinfo))
        {
            if (offset)
            { 
                *offset = displacement;
            }

            if (offset || (displacement == 0))
            {
                strncpy(sym_name, pinfo->Name, sym_buf_siz);
                sym_name[sym_buf_siz - 1] = 0;

                return 1;
            }
        }

        return 0;
    }

    int vmp_hlp_get_symbol2(struct vmp_hlp *mod, DWORD64 fa, char *sym_name, int sym_buf_siz, DWORD64 *offset)
    {
        return vmp_hlp_get_symbol(mod, (DWORD64)pe_loader_fa2rva(mod->pe_loader1, fa), sym_name, sym_buf_siz, offset);
    }

#ifdef __cplusplus
}
#endif
