#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <process.h>
#include <DbgHelp.h>
#include <stdio.h>
#include <assert.h>
#include "vmp_decoder.h"
#include "pe_loader.h"
#include "xed/xed-interface.h"
#include "xed/xed-address-width-enum.h"
#include "xed-symbol-table.h"
#include "mbytes.h"
#include "macro_list.h"
#include "vmp_hlp.h"
#include "x86_emu.h"

#define print_err   printf
#define time2s(_a)   ""


    typedef struct vmp_decoder
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
        unsigned int vmp_start_fa;

        xed_machine_mode_enum_t mmode;
        xed_address_width_enum_t stack_addr_width;

        int label_counts;

        struct {
            int     dump_inst;
            int     dump_dot_graph;

            struct vmp_hlp *hlp;
        } debug;

        struct {
            int counts;
            unsigned char *start[3];
            int size[3];

            int call_counts;
        } vmp_sections;

        unsigned char       *vmp_start_addr;
        int vmp_ret_counts;

#define VMP_X86_SET_CF_BIT(eflags)          ((eflags & 0x01) = 1)

        struct x86_emu_mod *emu;

        struct {
            struct vmp_cfg_node *start;

            struct vmp_cfg_node *list;
            int counts;
        } cfg;
    } vmp_decoder_t;

    typedef struct vmp_cfg_node
    {
        uint8_t *id;
        char name[32];
        int len;

        struct {
            unsigned already_dot_dump   : 1;
            unsigned vmp                : 16;
        } debug;

        struct {
            struct vmp_cfg_node *next;
            struct vmp_cfg_node *prev;
        } in_list;

        struct vmp_cfg_node *true_node;
        struct vmp_cfg_node *false_node;
        struct vmp_cfg_node *jmp_node;
    } vmp_cfg_node_t;

#define vmp_stack_push(_st, _val)       (_st[++_st##_i] = _val)
#define vmp_stack_is_empty(_st)         (_st##_i == -1)
#define vmp_stack_pop(_st)               (vmp_stack_is_empty(_st) ? NULL:_st[_st##_i--])
#define vmp_stack_top(_st)              (vmp_stack_is_empty(_st) ?  NULL:_st[_st##_i])

    static int vmp_addr_in_vmp_section(struct vmp_decoder *decoder, unsigned char *addr);
    static struct vmp_cfg_node *vmp_cfg_find(struct vmp_decoder *decoder, uint8_t *id);
    static int vmp_cfg_add_inst(struct vmp_cfg_node *cfg, uint8_t *addr, int len);
#define vmp_sym_addr(_decoder, _address)  (UINT64)(pe_loader_fa2rva(_decoder->pe_mod, (DWORD64)_address))

    struct vmp_decoder *vmp_decoder_create(char *filename, DWORD vmp_start_rva, int dump_pe)
    {
        struct vmp_decoder *mod = (struct vmp_decoder *)calloc(1, sizeof(mod[0]));
        char bak_filename[128];

        if (!vmp_start_rva || !filename)
        {
            printf("vmp_decoder_create() failed with invalid param. %s:%d\n", __FILE__, __LINE__);
            return NULL;
        }

        if (!mod)
        {
            printf("vmp_decoder_create() failed with calloc(). %s:%d\n", __FILE__, __LINE__);
            return NULL;
        }

        // 因为我们需要对去壳的vmp做地址的重映射工作，所以我们把文件从硬盘映射到内存不能是
        // 只读的，但是假如改成读写方式来映射，那么我在修改了重定位表后，也会同时修改文件
        // 所以我这里对命令输入的文件做了一个备份，然后修改这个备份的文件即可。
        sprintf(bak_filename, "%s.bak", filename);
        CopyFile(filename, bak_filename, FALSE);

        mod->pe_mod = pe_loader_create(bak_filename);
        if (NULL == mod->pe_mod)
        {
            printf("vmp_decoder_create() failed with pe_loader_create(). %s:%d\n", __FILE__, __LINE__);
            goto fail_label;
        }

        if (dump_pe)
        {
            pe_loader_dump(mod->pe_mod);
            return 0;
        }

        if (!vmp_start_rva)
        {
            vmp_start_rva = pe_loader_entry_point(mod->pe_mod);
        }
        mod->vmp_start_va = vmp_start_rva;
        strcpy_s(mod->filename, filename);

        mod->image_base = (unsigned char *)mod->pe_mod->image_base;
        mod->addr_start = ((unsigned char *)mod->image_base + (vmp_start_rva - 0x400000));
        mod->runtime_vaddr = mod->addr_start;

        xed_tables_init();
        mod->mmode = XED_MACHINE_MODE_LEGACY_32;
        mod->stack_addr_width = XED_ADDRESS_WIDTH_32b;

        mod->format_options.hex_address_before_symbolic_name = 1;
        mod->format_options.write_mask_curly_k0 = 1;
        mod->format_options.lowercase_hex = 1;

        mod->debug.dump_inst = 1;
        mod->debug.hlp = vmp_hlp_create(mod->pe_mod, filename, mod->pe_mod->file_handl, (char *)mod->pe_mod->image_base);
        if (!mod->debug.hlp)
        {
            printf("vmp_decoder_create() failed when vmp_hlp_create(). %s:%d\r\n", __FILE__, __LINE__);
        }

        if (pe_loader_section_find(mod->pe_mod, ".vmp0", &mod->vmp_sections.start[0], &mod->vmp_sections.size[0]))
        {
            mod->vmp_sections.counts++;
        }

        if (pe_loader_section_find(mod->pe_mod, ".vmp1", &mod->vmp_sections.start[1], &mod->vmp_sections.size[1]))
        {
            mod->vmp_sections.counts++;
        }

        if (0) //(!mod->vmp_sections.counts)
        {
            printf("vmp_decoder_create() failed with not found vmp section. %s:%d\r\n", __FILE__, __LINE__);
            goto fail_label;
        }

        struct x86_emu_create_param param;

        param.pe_mod = mod->pe_mod;
        param.hlp = mod->debug.hlp;

        mod->emu = x86_emu_create(&param);

        return mod;

    fail_label:
        if (mod)
        {
            vmp_decoder_destroy(mod);
        }
        return NULL;
    }

    void vmp_decoder_destroy(struct vmp_decoder *decoder)
    {
        if (decoder)
        {
            if (decoder->emu)
            {
                x86_emu_destroy(decoder->emu);
                decoder->emu = NULL;
            }
            free(decoder);
        }
    }

#define xed_success(ret)                (ret == XED_ERROR_NONE)

    int vmp_xed_disassembly_callback_function(xed_uint64_t address,
        char *sym_buf, xed_uint32_t buf_size, xed_uint64_t *offset, void *ctx)
    {
        struct vmp_decoder *decoder = (struct vmp_decoder *)ctx;
        int ret;

        sym_buf[0] = 0;
        ret = vmp_hlp_get_symbol(decoder->debug.hlp, (uint64_t)address - (uint64_t)decoder->image_base, sym_buf, buf_size, offset);
        if (ret)
        {
            //printf("sym[%s]\n", sym_buf);
        }

        return ret;
    }

    int vmp_decoder_dump_inst(struct vmp_decoder *decoder,
        xed_decoded_inst_t *xedd, xed_uint64_t runtime_instruction_address, char *buf, int buf_size)
    {
        int ret;

        xed_print_info_t pi;
        xed_init_print_info(&pi);

        pi.p = xedd;
        pi.blen = buf_size;
        pi.buf = buf;

        pi.context = decoder;

        pi.disassembly_callback = vmp_xed_disassembly_callback_function; //xed_disassembly_callback_function;
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

        return 0;
    }

    struct vmp_cfg_node *vmp_cfg_create (struct vmp_decoder *decoder, unsigned char *addr)
    {
        struct vmp_cfg_node *node = NULL;

        node = (struct vmp_cfg_node *)calloc(1, sizeof (node[0]));
        if (NULL == node)
        {
            printf("vmp_cfg_create() failed with calloc()");
            return NULL;
        }

        sprintf(node->name, "label%d", ++decoder->label_counts);
        node->id = addr;

        mlist_add(decoder->cfg, node, in_list);

        return node;
    }

    int vmp_cfg_node_update_vmp(struct vmp_cfg_node *node, int vmp)
    {
        if (!node->debug.vmp)
        {
            node->debug.vmp = vmp;
            sprintf(node->name, "vmp%d", node->debug.vmp);
        }
        return 0;
    }

    int vmp_cfg_node__dump(struct vmp_decoder *decoder, struct vmp_cfg_node *node)
    {
        struct vmp_cfg_node *list;
        int i;

        if (node->debug.already_dot_dump)
            return 0;

        node->debug.already_dot_dump = 1;

        for (i = 0, list = decoder->cfg.list; i < decoder->cfg.counts; i++, list = list->in_list.next)
        {
            fprintf(decoder->dot_graph_output, " %s [label=%s]", list->name, list->name);
        }

        for (i = 0, list = decoder->cfg.list; i < decoder->cfg.counts; i++, list = list->in_list.next)
        {
            if (list->jmp_node)
            {
                fprintf(decoder->dot_graph_output, "%s -> %s", list->name, list->jmp_node->name);
            }
            else if (list->true_node)
            {
                fprintf(decoder->dot_graph_output, "%s -> %s", list->name, list->true_node->name);
            }
        }

        return 0;
    }

    int vmp_cfg_node_dump (struct vmp_decoder *decoder, struct vmp_cfg_node *start)
    {
        fprintf(decoder->dot_graph_output, "digraph {\n");
        vmp_cfg_node__dump(decoder, start);
        fprintf(decoder->dot_graph_output, "}\n");

        return 0;
    }

    int vmp_decoder_run(struct vmp_decoder *decoder)
    {
        int  inst_in_vmp;
        xed_error_enum_t xed_error;
        xed_decoded_inst_t xedd;
        int decode_len, ok = 0, j, ret;
        struct vmp_cfg_node *cfg_node_stack[128];
        int cfg_node_stack_i = -1;
        struct vmp_cfg_node *cur_cfg_node = NULL, *t_cfg_node;
        char buf[64];
        static int vmp_start = 0, not_empty = 0;
        x86_emu_flow_analysis_t flow_analy;

        if (!decoder->dot_graph_output)
        {
            decoder->dot_graph_output = fopen("1.dot", "w");
        }

        while (1)
        {
            inst_in_vmp = 0;
            xed_decoded_inst_zero(&xedd);
            xed_decoded_inst_set_mode(&xedd, decoder->mmode, decoder->stack_addr_width);

            inst_in_vmp = vmp_addr_in_vmp_section(decoder, decoder->runtime_vaddr);

            if (inst_in_vmp)
            {
                if (!vmp_start)
                {
                    decoder->vmp_start_addr = decoder->runtime_vaddr;
                    decoder->vmp_start_fa = (uint32_t)((DWORD64)decoder->runtime_vaddr - (DWORD64)decoder->pe_mod->image_base);
                    vmp_start = 1;
                    printf("Wooow, we found vmp start address. %s:%d\r\n", __FILE__, __LINE__);
                }

                if (!cur_cfg_node->debug.vmp)
                {
                    vmp_cfg_node_update_vmp(cur_cfg_node, ++decoder->vmp_sections.call_counts);
                }

                if (!not_empty && !x86_emu_stack_is_empty(decoder->emu))
                {
                    not_empty = 1;
                }
            }
            else
            {
                if (vmp_start)
                {
                    vmp_start = 0;
                    printf("Now, we out vmp address. %s:%d\r\n", __FILE__, __LINE__);
                }
            }

            if (not_empty && !inst_in_vmp && x86_emu_stack_is_empty(decoder->emu))
            {
                break;
            }

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

            if (decoder->debug.dump_inst)
            {
                printf("[%p]\t[%08x]", decoder->runtime_vaddr, 0x400000 + pe_loader_fa2rva(decoder->pe_mod, (uint64_t)decoder->runtime_vaddr));
                for (j = 0; j < cfg_node_stack_i; j++)
                {
                    printf("    ");
                }
                for (j = 0; j < decode_len; j++)
                {
                    printf ("%02x ", decoder->runtime_vaddr[j]);
                }
                for (j = decode_len; j < 14; j++)
                {
                    printf("   ");
                }
                vmp_decoder_dump_inst(decoder, &xedd, (xed_uint64_t)decoder->runtime_vaddr, buf, sizeof (buf) -1);
                printf("[%s]\n", buf);
            }

            if (!cur_cfg_node)
            {
                if (NULL == (cur_cfg_node = vmp_cfg_create(decoder, decoder->runtime_vaddr)))
                {
                    printf("vmp_decoder_run() failed when vmp_cfg_create(). %s:%d\r\n", __FILE__, __LINE__);
                    return NULL;
                }
                vmp_stack_push(cfg_node_stack, cur_cfg_node);
            }

            cur_cfg_node = vmp_stack_top(cfg_node_stack);
            assert(cur_cfg_node);


            memset(&flow_analy, 0, sizeof (flow_analy));
            ret = x86_emu_run(decoder->emu, decoder->runtime_vaddr, decode_len, &flow_analy);

            // 这个分析并非时纯的静态分析，实际上他一直在运算，所以我们在碰到条件跳转时，不
            // 分析那些走不到的分支，但是我们可以先把他加入进来
            if (flow_analy.jmp_type)
            {
                uint8_t *addr = ((flow_analy.jmp_type == X86_COND_JMP) || flow_analy.cond ? flow_analy.true_addr : flow_analy.false_addr);

                if (vmp_cfg_find(decoder, addr))
                {
                }
                else
                {
                    t_cfg_node = vmp_cfg_create(decoder, flow_analy.true_addr);
                    cur_cfg_node->jmp_node = t_cfg_node;
                    cur_cfg_node = t_cfg_node;
                    decoder->runtime_vaddr = flow_analy.true_addr;
                }
            }
            else
            {
                decoder->runtime_vaddr += decode_len;
                vmp_cfg_add_inst(cur_cfg_node, decoder->runtime_vaddr, decode_len);
            }
        }

        if (decoder->dot_graph_output)
        {
            vmp_cfg_node_dump(decoder, cur_cfg_node);
            fclose(decoder->dot_graph_output);
            system("dot.exe -Tpng -o 1.png 1.dot");
        }

        return 0;
    }

    // private function
    /*
    @return     1           yes
                =0          no
    */
    static int vmp_addr_in_vmp_section (struct vmp_decoder *decoder, unsigned char *addr)
    {
        int i;

        for (i = 0; i < decoder->vmp_sections.counts; i++)
        {
            if ((addr >= decoder->vmp_sections.start[0])
                && (addr < decoder->vmp_sections.start[0] + decoder->vmp_sections.size[0]))
            {
                return 1;
            }
        }

        return 0;
    }

    static int vmp_cfg_seperate(struct vmp_decoder *decoder,
        struct vmp_cfg_node *cur_node,
        uint8_t *addr, struct vmp_cfg_node **head, struct vmp_cfg_node **tail)
    {
        return 0;
    }

    static struct vmp_cfg_node *vmp_cfg_find(struct vmp_decoder *decoder, uint8_t *id)
    {
        int i;
        struct vmp_cfg_node *list;

        for (i = 0, list = decoder->cfg.list; i < decoder->cfg.counts; i++, list = list->in_list.next)
        {
            if (id == list->id)
                return list;
        }

        return NULL;
    }

    static int vmp_cfg_add_inst(struct vmp_cfg_node *cfg, uint8_t *addr, int len)
    {
        if ((cfg->id + cfg->len) == addr)
        {
            cfg->len += len;
            return 0;
        }

        return -1;
    }


#ifdef __cplusplus
}
#endif
