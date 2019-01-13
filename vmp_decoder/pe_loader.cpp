
#ifdef __cplusplus
extern "C" {
#endif

#include "pe_loader.h"
#include <DbgHelp.h>
#include <winnt.h>
#include <stdio.h>
#include "mbytes.h"

#pragma comment(lib, "dbghelp.lib")

    struct pe_loader *pe_loader_create(LPCTSTR filename)
    {
#undef func_format
#undef func_format_s
#define func_format     "pe_loader_create(filename:%s)"
#define func_format_s   filename
        struct pe_loader *mod = (struct pe_loader *)calloc(1, sizeof(mod[0]));
        PIMAGE_FILE_HEADER pfile_header;

        if (NULL == mod)
        {
            return NULL;
        }

        if (NULL == filename)
        {
            printf("pe_loader_create() faile with path is empty\n");
            return NULL;
        }
        strcpy(mod->filename, filename);

        mod->file_handl = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
        if (!mod->file_handl)
        {
            printf("pe_loader_create() faile with CreateFile()\n");
            goto fail_label;
        }

        mod->map_handl = CreateFileMapping(mod->file_handl, NULL, PAGE_READONLY, 0, 0, NULL);
        if (!mod->map_handl)
        {
            printf("pe_loader_create() faile with CreateFileMapping()\n");
            goto fail_label;
        }

        mod->image_base = MapViewOfFile(mod->map_handl, FILE_MAP_READ, 0, 0, 0);
        if (!mod->image_base)
        {
            printf("pe_loader_create() faile with MapViewOfFile()\n");
            goto fail_label;
        }

        pfile_header = pe_loader_get_file_headers (mod);

        if (pfile_header->Machine == 0x14c)
        {
            //printf("[%s] file is x86 arch\n", mod->filename);
        }
        else if (pfile_header->Machine == 0x8664)
        { 
            mod->is_x64 = 1;
            //printf("[%s] file is x64 arch\n", mod->filename);
        }
        else
        {
            printf("[%s] file is un-recognized[%ul]. %s:%d\r\n", mod->filename, pfile_header->Machine, __FILE__, __LINE__);
        }

        if (mod->is_x64)
        { 
            printf("pe_loader() failed with un-support X64 arch. %s:%d\r\n", __FILE__, __LINE__);
        }

        return mod;

    fail_label:
        pe_loader_destroy(mod);

        return NULL;
    }

    void             pe_loader_destroy(struct pe_loader *mod)
    {
        if (mod)
        {
            if (mod->image_base)
                UnmapViewOfFile(mod->map_handl);

            if (mod->map_handl)
                CloseHandle(mod->map_handl);

            if (mod->file_handl)
                CloseHandle(mod->file_handl);
            free(mod);
        }
    }

#define counts_of_array(_a)             (sizeof (_a) / sizeof (_a[0]))


    PIMAGE_DOS_HEADER pe_loader_get_dos_header (struct pe_loader *mod)
    {
        return (PIMAGE_DOS_HEADER)mod->image_base;
    }

    PIMAGE_NT_HEADERS pe_loader_get_nt_header (struct pe_loader *mod)
    {
        PIMAGE_DOS_HEADER pdos_header;

        pdos_header = (PIMAGE_DOS_HEADER)mod->image_base;

        return (PIMAGE_NT_HEADERS)(((char *)pdos_header + pdos_header->e_lfanew));
    }

    PIMAGE_FILE_HEADER pe_loader_get_file_headers (struct pe_loader *mod)
    {
        PIMAGE_NT_HEADERS pnt_header = pe_loader_get_nt_header(mod);

        return &pnt_header->FileHeader;
    }

    int     pe_loader_is_x64 (struct pe_loader *mod)
    {
        return mod->is_x64;
    }

    long pe_loader_section_find(struct pe_loader *mod, const char *sec_name, unsigned char **section_start, int *section_size)
    {
        PIMAGE_DOS_HEADER pdos_header;
        PIMAGE_NT_HEADERS32 pnt_headder;
        PIMAGE_FILE_HEADER pfile_header;
        PIMAGE_OPTIONAL_HEADER32 popt_header;
        PIMAGE_SECTION_HEADER psec_header;
        int i, len = (int)strlen(sec_name), found = 0;
        if (len > IMAGE_SIZEOF_SHORT_NAME)
            len = IMAGE_SIZEOF_SHORT_NAME;

        if (mod->is_x64)
        { 
            printf("pe_loader_section_find() not support x64 arch. %s:%d\r\n", __FILE__, __LINE__);
            return 0;
        }

        pdos_header = (PIMAGE_DOS_HEADER)mod->image_base;
        pnt_headder = (PIMAGE_NT_HEADERS32)(((char *)pdos_header + pdos_header->e_lfanew));
        popt_header = &pnt_headder->OptionalHeader;
        pfile_header = &pnt_headder->FileHeader;
        psec_header = (PIMAGE_SECTION_HEADER)((char *)popt_header + sizeof(popt_header[0]));

        for (i = 0; i < pfile_header->NumberOfSections; i++)
        {
            if (psec_header->SizeOfRawData == 0)
                continue;

            if (strncmp((const char *)psec_header[i].Name, sec_name, len) == 0)
            {
                found = 1;
            }

            if (!found)
                continue;

            if (section_start)
            { 
                *section_start = (unsigned char *)mod->image_base + psec_header[i].PointerToRawData;
            }

            if (section_size)
            { 
                *section_size = (psec_header[i].SizeOfRawData > 0) ?
                    psec_header[i].SizeOfRawData: psec_header[i].SizeOfRawData;
            }

            return 1;
        }

        return 0;
    }

    int pe_loader_sym_find (struct pe_loader *mod, DWORD iat_addr, char *sym_name, int sym_buf_siz)
    {
        PIMAGE_DOS_HEADER pdos_header;
        PIMAGE_NT_HEADERS32 pnt_headder;
        PIMAGE_OPTIONAL_HEADER32 popt_header = NULL;
        DWORD rfa, rva;
        IMAGE_IMPORT_BY_NAME *ii_name;

        pdos_header = (PIMAGE_DOS_HEADER)mod->image_base;
        pnt_headder = (PIMAGE_NT_HEADERS32)(((char *)pdos_header + pdos_header->e_lfanew));
        popt_header = &pnt_headder->OptionalHeader;

        //printf("iat addr = 0x%08x, popt_head = 0x%08x\r\n", iat_addr, popt_header->ImageBase);

        rfa = pe_loader_rva2rfa(mod, iat_addr - popt_header->ImageBase);
        if (!rfa)
        {
            printf("pe_loader_sym_find() failed when pe_loader_rva2fa(). %s:%d\r\n", __FILE__, __LINE__);
            return -1;
        }

        rva = mbytes_read_int_little_endian_4b(((char *)(mod->image_base) + rfa));
        if (rva > popt_header->ImageBase)
        { 
            rva -= popt_header->ImageBase;
        }
        if (rva && (rfa = pe_loader_rva2rfa(mod, rva)))
        { 
            ii_name = (IMAGE_IMPORT_BY_NAME *)((char *)mod->image_base + rfa);
            strcpy(sym_name, ii_name->Name);
        }

        return 0;
    }

    DWORD pe_loader_entry_point (struct pe_loader *mod)
    {
        PIMAGE_DOS_HEADER pdos_header;
        PIMAGE_NT_HEADERS32 pnt_headder;
        PIMAGE_NT_HEADERS64 pnt_headder64;
        PIMAGE_OPTIONAL_HEADER32 popt_header = NULL;
        PIMAGE_OPTIONAL_HEADER64 popt_header64 = NULL;

        pdos_header = (PIMAGE_DOS_HEADER)mod->image_base;
        if (mod->is_x64)
        { 
            pnt_headder64 = (PIMAGE_NT_HEADERS64)(((char *)pdos_header + pdos_header->e_lfanew));
            popt_header64 = &pnt_headder64->OptionalHeader;

            return popt_header64->AddressOfEntryPoint;
        }
        else
        { 
            pnt_headder = (PIMAGE_NT_HEADERS32)(((char *)pdos_header + pdos_header->e_lfanew));
            popt_header = &pnt_headder->OptionalHeader;

            return popt_header->AddressOfEntryPoint;
        }
    }

    void pe_loader_dump(struct pe_loader *mod)
    {
        PIMAGE_DOS_HEADER pdos_header;
        PIMAGE_NT_HEADERS32 pnt_headder;
        PIMAGE_NT_HEADERS64 pnt_headder64;
        PIMAGE_FILE_HEADER pfile_header;
        PIMAGE_OPTIONAL_HEADER32 popt_header = NULL;
        PIMAGE_OPTIONAL_HEADER64 popt_header64 = NULL;
        PIMAGE_SECTION_HEADER psec_header;
        DWORD              va;
        int i;

        pdos_header = (PIMAGE_DOS_HEADER)mod->image_base;
        if (mod->is_x64)
        { 
            pnt_headder64 = (PIMAGE_NT_HEADERS64)(((char *)pdos_header + pdos_header->e_lfanew));
            popt_header64 = &pnt_headder64->OptionalHeader;
            pfile_header = &pnt_headder64->FileHeader;
            psec_header = (PIMAGE_SECTION_HEADER)((char *)popt_header64 + sizeof(popt_header64[0]));

            printf("EntryPoint          = %08x,             Subsystem:              = %08x\n", popt_header64->AddressOfEntryPoint, popt_header64->Subsystem);
            printf("ImageBase           = %016I64x,         NumberOfSections:       = %08x\n", popt_header64->ImageBase, pfile_header->NumberOfSections);
            printf("SizeOfImage         = %08x,             TimeDateStamp:          = %08x\n", popt_header64->SizeOfImage, pfile_header->TimeDateStamp);
            printf("BaseOfCode          = %08x,             SizeOfHeaders:          = %08x\n", popt_header64->BaseOfCode, popt_header64->SizeOfHeaders);
            printf("BaseOfData          = %08x,             Characteristics:        = %08x\n", 0, pfile_header->Characteristics);
            printf("SectionAlignment:   = %08x,             Checksum:               = %08x\n", popt_header64->SectionAlignment, popt_header64->CheckSum);
            printf("FileAlignemtn:      = %08x,             SizeOfOptionHeaders:    = %08x\n", popt_header64->FileAlignment, pfile_header->SizeOfOptionalHeader);
            printf("Magic:              = %08x,             NumOfRvaAndSizes:       = %08x\n", popt_header64->Magic, popt_header64->NumberOfRvaAndSizes);
            printf("FilSignature:       = %08x,             NumOfRvaAndSizes:       = %08x\n", pfile_header->Machine, popt_header64->NumberOfRvaAndSizes);
        }
        else
        { 
            pnt_headder = (PIMAGE_NT_HEADERS32)(((char *)pdos_header + pdos_header->e_lfanew));
            popt_header = &pnt_headder->OptionalHeader;
            pfile_header = &pnt_headder->FileHeader;
            psec_header = (PIMAGE_SECTION_HEADER)((char *)popt_header + sizeof(popt_header[0]));

            printf("EntryPoint          = %08x,         Subsystem:              = %08x\n", popt_header->AddressOfEntryPoint, popt_header->Subsystem);
            printf("ImageBase           = %08x,         NumberOfSections:       = %08x\n", popt_header->ImageBase, pfile_header->NumberOfSections);
            printf("SizeOfImage         = %08x,         TimeDateStamp:          = %08x\n", popt_header->SizeOfImage, pfile_header->TimeDateStamp);
            printf("BaseOfCode          = %08x,         SizeOfHeaders:          = %08x\n", popt_header->BaseOfCode, popt_header->SizeOfHeaders);
            printf("BaseOfData          = %08x,         Characteristics:        = %08x\n", popt_header->BaseOfData, pfile_header->Characteristics);
            printf("SectionAlignment:   = %08x,         Checksum:               = %08x\n", popt_header->SectionAlignment, popt_header->CheckSum);
            printf("FileAlignemtn:      = %08x,         SizeOfOptionHeaders:    = %08x\n", popt_header->FileAlignment, pfile_header->SizeOfOptionalHeader);
            printf("Magic:              = %08x,         NumOfRvaAndSizes:       = %08x\n", popt_header->Magic, popt_header->NumberOfRvaAndSizes);
            printf("FilSignature:       = %08x,         NumOfRvaAndSizes:       = %08x\n", pfile_header->Machine, popt_header->NumberOfRvaAndSizes);
        }

        printf("\n\n\n");
        printf("DATA Directory\n\n");

        if (mod->is_x64)
        { 
            for (i = 0; i < counts_of_array(popt_header64->DataDirectory); i++)
            {
                va = popt_header64->DataDirectory[i].VirtualAddress;
                printf("[%08x,%08x]\n", va, popt_header64->DataDirectory[i].Size);
            }
        }
        else
        { 
            for (i = 0; i < counts_of_array(popt_header->DataDirectory); i++)
            {
                va = popt_header->DataDirectory[i].VirtualAddress;
                printf("[%08x,%08x]\n", va, popt_header->DataDirectory[i].Size);
            }
        }

        printf("rva = %ul\n", (unsigned int)((UINT64)psec_header - (UINT64)mod->image_base));
        printf("\n\nSection Table\n\n");
        for (i = 0; i < pfile_header->NumberOfSections; i++)
        {
            printf("%8s, %08x, %08x, %08x, %08x\n", 
                psec_header[i].Name, psec_header[i].VirtualAddress, psec_header[i].Misc.VirtualSize,
                psec_header[i].PointerToRawData, psec_header[i].SizeOfRawData);
        }
    }

DWORD pe_loader_rva2rfa(struct pe_loader *mod, DWORD rva)
{
    PIMAGE_DOS_HEADER pdos_header;
    PIMAGE_NT_HEADERS32 pnt_headder;
    PIMAGE_FILE_HEADER pfile_header;
    PIMAGE_OPTIONAL_HEADER32 popt_header = NULL;
    PIMAGE_SECTION_HEADER psec_header;
    DWORD delta;
    int i;

    if (mod->is_x64)
        return 0;

    pdos_header = (PIMAGE_DOS_HEADER)mod->image_base;
    pnt_headder = (PIMAGE_NT_HEADERS32)(((char *)pdos_header + pdos_header->e_lfanew));
    popt_header = &pnt_headder->OptionalHeader;
    pfile_header = &pnt_headder->FileHeader;
    psec_header = (PIMAGE_SECTION_HEADER)((char *)popt_header + sizeof(popt_header[0]));

    for (i = 0; i < pfile_header->NumberOfSections; i++)
    {
        if ((rva >= psec_header[i].VirtualAddress)
            && (rva < (psec_header[i].VirtualAddress + psec_header[i].Misc.VirtualSize)))
        {
            delta = (psec_header[i].VirtualAddress - psec_header[i].PointerToRawData);
            return rva - delta;
        }
    }

    printf("pe_loader_rva2fa() failed with invalid param[rva=0x%08x]. %s:%d\r\n", rva, __FILE__, __LINE__);

    return 0;
}

DWORD pe_loader_fa2rva(struct pe_loader *mod, DWORD64 fa)
{
    DWORD rfa;

    PIMAGE_DOS_HEADER pdos_header;
    PIMAGE_NT_HEADERS32 pnt_headder;
    PIMAGE_FILE_HEADER pfile_header;
    PIMAGE_OPTIONAL_HEADER32 popt_header = NULL;
    PIMAGE_SECTION_HEADER psec_header;
    DWORD delta;
    int i;

    if (mod->is_x64)
    { 
        printf("pe_loader_fa2rva() failed with un-support x64\n");
        return 0;
    }


    pdos_header = (PIMAGE_DOS_HEADER)mod->image_base;
    pnt_headder = (PIMAGE_NT_HEADERS32)(((char *)pdos_header + pdos_header->e_lfanew));
    popt_header = &pnt_headder->OptionalHeader;
    pfile_header = &pnt_headder->FileHeader;
    psec_header = (PIMAGE_SECTION_HEADER)((char *)popt_header + sizeof(popt_header[0]));

    if ((fa > (DWORD64)mod->image_base) && (fa > popt_header->ImageBase))
    {
        rfa = (DWORD)(fa - (DWORD64)mod->image_base);
    }
    else
    { 
        rfa = (DWORD)(fa - (DWORD64)popt_header->ImageBase);
    }

    for (i = 0; i < pfile_header->NumberOfSections; i++)
    {
        if ((rfa >= psec_header[i].PointerToRawData)
            && (rfa < (psec_header[i].PointerToRawData + psec_header[i].SizeOfRawData)))
        {
            delta = (psec_header[i].VirtualAddress - psec_header[i].PointerToRawData);
            return (rfa + delta);
        }
    }

    return 0;
}

DWORD64 pe_loader_fa_fix(struct pe_loader *mod, DWORD64 fa, int rva)
{
    PIMAGE_DOS_HEADER pdos_header;
    PIMAGE_NT_HEADERS32 pnt_headder;
    PIMAGE_FILE_HEADER pfile_header;
    PIMAGE_OPTIONAL_HEADER32 popt_header = NULL;
    PIMAGE_SECTION_HEADER psec_header;
    DWORD delta, new_rva, rfa;
    int i, j;

    if (mod->is_x64)
    { 
        printf("pe_loader_fa2rva() failed with un-support x64\n");
        return 0;
    }

    pdos_header = (PIMAGE_DOS_HEADER)mod->image_base;
    pnt_headder = (PIMAGE_NT_HEADERS32)(((char *)pdos_header + pdos_header->e_lfanew));
    popt_header = &pnt_headder->OptionalHeader;
    pfile_header = &pnt_headder->FileHeader;
    psec_header = (PIMAGE_SECTION_HEADER)((char *)popt_header + sizeof(popt_header[0]));

    if ((fa > (DWORD64)mod->image_base) && (fa > popt_header->ImageBase))
    {
        rfa = (DWORD)(fa - (DWORD64)mod->image_base);
    }
    else
    { 
        rfa = (DWORD)(fa - (DWORD64)popt_header->ImageBase);
    }

#define PE_RFA_IN_SECTION(_rfa, _sec)           (((_rfa) >= (_sec).PointerToRawData) && ((_rfa) < ((_sec).PointerToRawData + (_sec).SizeOfRawData)))
#define PE_RVA_IN_SECTION(_rva, _sec)           (((_rva) >= (_sec).VirtualAddress) && ((_rva) < ((_sec).VirtualAddress + (_sec).Misc.VirtualSize)))

    for (i = 0; i < pfile_header->NumberOfSections; i++)
    {
        if (PE_RFA_IN_SECTION(rfa, psec_header[i]))
        {
            if (PE_RFA_IN_SECTION(rfa + rva, psec_header[i]))
            {
                return (DWORD64)mod->image_base + rfa + rva;
            }

            delta = (psec_header[i].VirtualAddress - psec_header[i].PointerToRawData);
            new_rva = rfa + delta;
            break;
        }
    }

    if (i == pfile_header->NumberOfSections)
    {
        printf("pe_loadef_fa_fix() failed with address[fa:%lld]. %s:%d\r\n", fa, __FILE__, __LINE__);
        return 0;
    }

    new_rva += rva;

    for (j = 0; j < pfile_header->NumberOfSections; j++)
    {
        if (PE_RVA_IN_SECTION(new_rva, psec_header[j]))
        {
            rfa = new_rva - psec_header[j].VirtualAddress;

            return (DWORD64)mod->image_base + rfa + psec_header[j].PointerToRawData;
        }
    }

    return 0;
}

#ifdef __cplusplus
}
#endif
