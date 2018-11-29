#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <process.h>
#include <DbgHelp.h>
#include <stdio.h>
#include "vmp_decoder.h"
#include "pe_loader.h"
#include "xed/xed-interface.h"
#include "xed/xed-address-width-enum.h"
#include "xed-symbol-table.h"
#include "udhelp.h"


    struct vmp_decoder
    {
        char filename[MAX_PATH];
        struct pe_loader *pe_mod;

        unsigned char* addr_start;
        xed_int64_t addr_end;
        xed_int64_t fake_base;
        xed_bool_t resync;  /* turn on/off symbol-based resynchronization */
        xed_bool_t line_numbers;    /* control for printing file/line info */
        FILE *dot_graph_output;

        xed_format_options_t format_options;
        xed_operand_enum_t operand;
        xed_uint32_t operand_value;

        xed_uint64_t errors;

        unsigned char *image_base;  // start of image
        unsigned char *inst_start;  // start of instruction to decode region
        unsigned char *inst_end;    // end of region

        // where this region would live at runtime
        unsigned char *runtime_vaddr;
        // where to start in program space, if not zero
        unsigned char *runtime_vaddr_disas_start;
        // where to stop in program space, if not zero
        unsigned char *runtime_vaddr_disas_end;

        xed_bool_t ast;

        unsigned int vmp_start_va;
        xed_machine_mode_enum_t mmode;
        xed_address_width_enum_t stack_addr_width;

        dbg_help_client_t vmp_help;
    };

    struct vmp_decoder *vmp_decoder_create(char *filename, DWORD vmp_start_rva)
    {
        struct vmp_decoder *mod = (struct vmp_decoder *)calloc(1, sizeof(mod[0]));

        if (!mod)
        {
            printf("vmp_decoder_create() failed with calloc(). %s:%d\n", __FILE__, __LINE__);
            return NULL;
        }

        mod->pe_mod = pe_loader_create(filename);
        if (NULL == mod->pe_mod)
        {
            printf("vmp_decoder_create() failed with pe_loader_create(). %s:%d\n", __FILE__, __LINE__);
            goto fail_label;
        }

        //pe_loader_dump(mod->pe_mod);

        if (!vmp_start_rva)
        { 
            vmp_start_rva = pe_loader_entry_point(mod->pe_mod);
            printf("Entry Point = %u\n", vmp_start_rva);
        }
        mod->vmp_start_va = vmp_start_rva;
        strcpy_s(mod->filename, filename);

        mod->image_base = (unsigned char *)mod->pe_mod->image_base;
        mod->addr_start = ((unsigned char *)mod->image_base + pe_loader_rva2fa(mod->pe_mod, vmp_start_rva));

        printf("image_base = %p, addr_start = %p\n", mod->image_base, mod->addr_start);

        mod->runtime_vaddr = mod->addr_start;

        xed_tables_init();
        mod->mmode = XED_MACHINE_MODE_LEGACY_32;
        mod->stack_addr_width = XED_ADDRESS_WIDTH_32b;

        mod->format_options.hex_address_before_symbolic_name = 1;
        mod->format_options.write_mask_curly_k0 = 1;
        mod->format_options.lowercase_hex = 1;
        mod->vmp_help.init(filename, NULL);

        return mod;

    fail_label:
        return NULL;
    }

    void vmp_decoder_destroy(struct vmp_decoder *decoder)
    {
        if (decoder)
        {
            free(decoder);
        }
    }

#define xed_success(ret)                (ret == XED_ERROR_NONE)

    int vmp_decoder_dump_inst(struct vmp_decoder *decoder,
        xed_decoded_inst_t *xedd, xed_uint64_t runtime_instruction_address)
    {
        char buf[64];
        int buf_len = sizeof(buf), ret;

        xed_print_info_t pi;
        xed_init_print_info(&pi);

        pi.p = xedd;
        pi.blen = buf_len;
        pi.buf = buf;

        pi.disassembly_callback = NULL; //xed_disassembly_callback_function;
        pi.runtime_address = runtime_instruction_address;
        //use default format option, INTEL, dst operand on the left
        pi.format_options_valid = 1;
        pi.format_options = decoder->format_options;
        pi.buf[0] = 0;

        ret = xed_format_generic(&pi);
        if (!ret)
        {
            pi.blen = xed_strncpy(pi.buf, "Error disassembing ", pi.blen);
            pi.blen = xed_strncat(pi.buf, xed_syntax_enum_t2str(pi.syntax), pi.blen);
            pi.blen = xed_strncat(pi.buf, " syntax.", pi.blen);
        }

        printf("[%s]\n", buf);

        return 0;
    }

    int vmp_decoder_run(struct vmp_decoder *decoder)
    {
        int  num_of_inst = 15;
        xed_error_enum_t xed_error;
        xed_decoded_inst_t xedd;
        int decode_len, ok = 0, i;

        if (decoder->dot_graph_output)
        {
        }

        for (i = 0; i < num_of_inst; i++)
        { 
            xed_decoded_inst_zero(&xedd);
            xed_decoded_inst_set_mode(&xedd, decoder->mmode, decoder->stack_addr_width);

            xed_error = xed_decode(&xedd, decoder->runtime_vaddr, 15);
            if (xed_error != XED_ERROR_NONE)
            {
                printf("vmp_decoder_run() failed with (%s)xed_decode(). %s:%d\n",
                    xed_error_enum_t2str(xed_error), __FILE__, __LINE__);
                return -1;
            }

            decode_len = xed_decoded_inst_get_length(&xedd);
            if (!decode_len)
                decode_len = 1;

            vmp_decoder_dump_inst(decoder, &xedd, (xed_uint64_t)decoder->runtime_vaddr);

            decoder->runtime_vaddr += decode_len;
        }

        return 0;
    }


#ifdef __cplusplus
}
#endif
