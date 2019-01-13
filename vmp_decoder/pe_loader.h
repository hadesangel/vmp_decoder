

#ifndef __pe_loader_h__
#define __pe_loader_h__

#include <windows.h>

struct pe_loader
{
    char    filename[256];
    
    HANDLE  file_handl;
    HANDLE  map_handl;
    LPVOID  image_base;

    int     is_x64;
};


struct pe_loader *pe_loader_create(LPCTSTR path);
void pe_loader_destroy(struct pe_loader *mod);
void pe_loader_dump(struct pe_loader *mod);
long pe_loader_section_find(struct pe_loader *mod, const char *sec_name, unsigned char **section_start, int *section_size);
int pe_loader_sym_find(struct pe_loader *mod, DWORD rva, char *sym_name, int sym_buf_siz);
// virtual address to file address
DWORD pe_loader_rva2rfa(struct pe_loader *mod, DWORD rva);
DWORD pe_loader_fa2rva(struct pe_loader *mod, DWORD64 fa);
DWORD64 pe_loader_fa_fix(struct pe_loader *mod, DWORD64 fa, int rva);
DWORD pe_loader_entry_point(struct pe_loader *mod);
PIMAGE_DOS_HEADER pe_loader_get_dos_header(struct pe_loader *mod);
PIMAGE_NT_HEADERS pe_loader_get_nt_header(struct pe_loader *mod);
PIMAGE_FILE_HEADER pe_loader_get_file_headers(struct pe_loader *mod);


#endif