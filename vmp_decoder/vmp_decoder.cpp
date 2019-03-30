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
#include <time.h>

#define print_err   printf
#define time2s(_a)   ""


    typedef struct vmp_decoder
    {
        char filename[MAX_PATH];
        struct pe_loader *pe_mod;

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

        unsigned char *entry_of_point;

        unsigned char *vmp_act_start_vaddr;
        // where to start in program space, if not zero
        unsigned char *runtime_vaddr_disas_start;
        // where to stop in program space, if not zero
        unsigned char *runtime_vaddr_disas_end;

        xed_bool_t ast;

        unsigned int vmp_start_va;

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

    struct vmp_cfg_node_link
    {
        struct vmp_cfg_node_link *next;
        struct vmp_cfg_node *node;
    };

    typedef struct vmp_cfg_node
    {
        uint8_t *id;
        char name[32];
        int len;

        struct {
            unsigned already_dot_dump   : 1;
            unsigned vmp                : 16;
            unsigned external_call      : 1;
        } debug;

        struct {
            struct vmp_cfg_node *next;
            struct vmp_cfg_node *prev;
        } in_list;

        struct 
        {
            struct vmp_cfg_node_link *list;
            int count;
        } trues;

        struct
        {
        } falses;

        struct
        {
            struct vmp_cfg_node_link *list;
            int count;
        } jmps;
    } vmp_cfg_node_t;

#define vmp_stack_push(_st, _val)       (_st[++_st##_i] = _val)
#define vmp_stack_is_empty(_st)         (_st##_i == -1)
#define vmp_stack_pop(_st)               (vmp_stack_is_empty(_st) ? NULL:_st[_st##_i--])
#define vmp_stack_top(_st)              (vmp_stack_is_empty(_st) ?  NULL:_st[_st##_i])

    static int vmp_addr_in_vmp_section(struct vmp_decoder *decoder, unsigned char *addr);
    static struct vmp_cfg_node *vmp_cfg_find(struct vmp_decoder *decoder, uint8_t *id);
    static int vmp_cfg_add_inst(struct vmp_cfg_node *cfg, uint8_t *addr, int len);
    unsigned char *vmp_decoder_find_vmp_start_addr(struct vmp_decoder *decoder);
    static int vmp_cfg_add_edges(struct vmp_decoder *decoder,
        struct vmp_cfg_node *from, struct vmp_cfg_node *to, int jmp_type);
#define vmp_sym_addr(_decoder, _address)  (UINT64)(pe_loader_fa2rva(_decoder->pe_mod, (DWORD64)_address))

    struct vmp_decoder *vmp_decoder_create(char *filename, DWORD vmp_start_va, int dump_pe)
    {
        struct vmp_decoder *mod = (struct vmp_decoder *)calloc(1, sizeof(mod[0]));
        char bak_filename[128];

        if (!filename)
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


        mod->image_base = (unsigned char *)mod->pe_mod->image_base;

        strcpy_s(mod->filename, filename);

        xed_tables_init();
        mod->mmode = XED_MACHINE_MODE_LEGACY_32;
        mod->stack_addr_width = XED_ADDRESS_WIDTH_32b;

        mod->format_options.hex_address_before_symbolic_name = 1;
        mod->format_options.write_mask_curly_k0 = 1;
        mod->format_options.lowercase_hex = 1;

        mod->debug.dump_inst = 1;
        mod->debug.hlp = vmp_hlp_create(filename);
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

        if (!mod->vmp_sections.counts)
        {
            printf("vmp_decoder_create() failed with not found vmp section. %s:%d\r\n", __FILE__, __LINE__);
            goto fail_label;
        }

        struct x86_emu_create_param param;

#define FAKE_IMAGE_BASE                 0x400000

        param.pe_mod = mod->pe_mod;
        param.hlp = mod->debug.hlp;

        mod->emu = x86_emu_create(&param);

        mod->entry_of_point = ((unsigned char *)mod->image_base + pe_loader_entry_point(mod->pe_mod));

        if (!vmp_start_va)
        {
            mod->vmp_act_start_vaddr  = vmp_decoder_find_vmp_start_addr (mod);
        }
        else
        {
            mod->vmp_act_start_vaddr = ((unsigned char *)mod->image_base + (vmp_start_va - FAKE_IMAGE_BASE));
        }

        if (!mod->vmp_act_start_vaddr)
        {
            printf("vmp_decoder_create() failed with find vmp start address(). %s:%d\n", __FILE__, __LINE__);
            goto fail_label;
        }

        mod->vmp_start_va = vmp_start_va;

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

    int vmp_decoder_format_inst(struct vmp_decoder *decoder,
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

    struct vmp_cfg_node *vmp_cfg_create (struct vmp_decoder *decoder, unsigned char *addr, int iat_call)
    {
        struct vmp_cfg_node *node = NULL;
        //char sym_name[128];

        node = (struct vmp_cfg_node *)calloc(1, sizeof (node[0]));
        if (NULL == node)
        {
            printf("vmp_cfg_create() failed with calloc()");
            return NULL;
        }

        //if (vmp_hlp_get_symbol(decoder->debug.hlp, addr - decoder->image_base, sym_name, sizeof (sym_name), NULL))
        if (iat_call)
        {
            sprintf(node->name, "%s", ((unsigned char **)addr)[0]);
            node->debug.external_call = 1;
        }
        else
        {
            sprintf(node->name, "label%d", ++decoder->label_counts);
        }

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
        struct vmp_cfg_node_link *link;
        int i, j;

        if (node->debug.already_dot_dump)
            return 0;

        node->debug.already_dot_dump = 1;

        for (i = 0, list = decoder->cfg.list; i < decoder->cfg.counts; i++, list = list->in_list.next)
        {
            if (list->debug.external_call)
            { 
                fprintf(decoder->dot_graph_output, " %s [style=\"filled\",color=red, label=%s];\n", list->name, list->name);
            }
            else
            { 
                fprintf(decoder->dot_graph_output, " %s [label=%s];\n", list->name, list->name);
            }
        }

        for (i = 0, list = decoder->cfg.list; i < decoder->cfg.counts; i++, list = list->in_list.next)
        {
            for (j = 0, link = list->jmps.list; j < list->jmps.count; j++, link = link->next)
            {
                fprintf(decoder->dot_graph_output, "%s -> %s;\n", list->name, link->node->name);
            }

            for (j = 0, link = list->trues.list; j < list->trues.count; j++, link = link->next)
            {
                fprintf(decoder->dot_graph_output, "%s -> %s;\n", list->name, link->node->name);
            }
        }

        return 0;
    }

    int vmp_cfg_dump (struct vmp_decoder *decoder, struct vmp_cfg_node *start)
    {
        fprintf(decoder->dot_graph_output, "digraph {\n");
        vmp_cfg_node__dump(decoder, start);
        fprintf(decoder->dot_graph_output, "}\n");

        return 0;
    }

    int vmp_decoder_dump_inst(struct vmp_decoder *decoder, 
        xed_decoded_inst_t *xedd,
        int indent, unsigned char *inst, int inst_len)
    {
        char buf[128];
        int i;

        printf("[%p]\t[%08x]", inst, FAKE_IMAGE_BASE + ((int)(inst - decoder->image_base)));
        for (i = 0; i < indent; i++)
        {
            printf("    ");
        }
        for (i = 0; i < inst_len; i++)
        {
            printf ("%02x ", inst[i]);
        }
        for (i = inst_len; i < 14; i++)
        {
            printf("   ");
        }
        vmp_decoder_format_inst(decoder, xedd, (xed_uint64_t)inst, buf, sizeof (buf) -1);
        printf("[%s]\n", buf);

        return 0;
    }

    unsigned char *vmp_decoder_find_vmp_start_addr(struct vmp_decoder *decoder)
    {
        xed_error_enum_t xed_error;
        xed_decoded_inst_t xedd;
        int decode_len;

        xed_decoded_inst_zero(&xedd);
        xed_decoded_inst_set_mode(&xedd, decoder->mmode, decoder->stack_addr_width);

        unsigned char *start_addr = decoder->entry_of_point;

        unsigned char *ret_addrs[128], *ret_addr, *jmp_addr;
        int ret_addrs_i = -1;

        unsigned char *inst_queue[5] = {0};
        int inst_queue_i = -1;

        unsigned char *jmp_queue[128];
        int jmp_queue_i = -1;
        int offset, inst_in_vmp;

#define counts_of_array(_a)             (sizeof (_a) / sizeof (_a[0]))

        while (start_addr && !(inst_in_vmp = vmp_addr_in_vmp_section(decoder, start_addr)))
        {
            xed_decoded_inst_zero(&xedd);
            xed_decoded_inst_set_mode(&xedd, decoder->mmode, decoder->stack_addr_width);

            inst_queue_i = ++inst_queue_i % counts_of_array(inst_queue);
            inst_queue[inst_queue_i] = start_addr;

            xed_error = xed_decode(&xedd, start_addr, 15);
            if (xed_error != XED_ERROR_NONE)
            {
                printf("vmp_decoder_find_vmp_start_addr() failed with (%s)xed_decode(). %s:%d\n",
                    xed_error_enum_t2str(xed_error), __FILE__, __LINE__);
                break;
            }

            decode_len = xed_decoded_inst_get_length(&xedd);
            if (!decode_len)
                decode_len = 1;

            // (decoder->debug.dump_inst && vmp_decoder_dump_inst(decoder, &xedd, ret_addrs_i + 1, start_addr, decode_len));

            switch (start_addr[0])
            {
            case 0x74: // jz
            case 0x75: // jnz
            case 0x7c: // jl
                jmp_addr = start_addr + decode_len + (int)start_addr[1];
                vmp_stack_push(jmp_queue, jmp_addr);
                start_addr += decode_len;
                break;

            case 0xeb: // near jmp
                start_addr = start_addr + decode_len + (int)start_addr[1];
                break;

            case 0xe8: // call
                ret_addr = start_addr + decode_len;
                vmp_stack_push(ret_addrs, ret_addr);
                vmp_stack_push(jmp_queue, NULL);
            case 0xe9: // jmp
                offset = mbytes_read_int_little_endian_4b(start_addr + 1);
                start_addr += offset + decode_len;
                break;

            case 0xf2: // bnd
                if (start_addr[1] != 0xc3)
                {
                    goto default_label;
                }
            case 0xc3: // ret
ret_label:
                if ((jmp_addr = vmp_stack_pop(jmp_queue)))
                {
                    start_addr = jmp_addr;
                    break;
                }

                start_addr = vmp_stack_pop(ret_addrs);
                break;

            case 0xff: // IAT jmp
                if (start_addr[1] == 0x15)
                { // IAT call
                    //ret_addr = start_addr + decode_len;
                    //vmp_stack_push(ret_addrs, ret_addr);
                    //vmp_stack_push(jmp_queue, NULL);
                    //offset = mbytes_read_int_little_endian_4b(start_addr + 2);
                    //start_addr += offset + decode_len;
                    start_addr += decode_len;
                }
                else if (start_addr[1] == 0x25)
                {
                    goto ret_label;
                    //offset = mbytes_read_int_little_endian_4b(start_addr + 2);
                    //start_addr += offset + decode_len;
                }
                else
                {
                    goto default_label;
                }
                break;

            default:
default_label:
                start_addr += decode_len;
                break;
            }
        }

        if (inst_in_vmp)
        {
            inst_queue_i -= 1;
            if (inst_queue_i < 0) inst_queue_i += counts_of_array(inst_queue);

            //decoder->vmp_start_addr = inst_queue[inst_queue_i];
            printf("Wooow, we found vmp start address. %p, %s:%d\r\n", inst_queue[inst_queue_i], __FILE__, __LINE__);
            return inst_queue[inst_queue_i];
        }

        return NULL;
    }

    int vmp_decoder_run(struct vmp_decoder *decoder)
    {
        int  inst_in_vmp;
        xed_error_enum_t xed_error;
        xed_decoded_inst_t xedd;
        int decode_len, ok = 0, ret;
        struct vmp_cfg_node *cfg_node_stack[128];
        int cfg_node_stack_i = -1;
        struct vmp_cfg_node *cur_cfg_node = NULL, *t_cfg_node;
        static int vmp_start = 0, not_empty = 0, iat_call;
        x86_emu_flow_analysis_t *flow_analy;

        if (!decoder->dot_graph_output)
        {
            decoder->dot_graph_output = fopen("1.dot", "w");
        }

        unsigned char *vmp_run_addr = decoder->vmp_act_start_vaddr;

        vmp_start = 1;

        while (1)
        {
            inst_in_vmp = 0;
            xed_decoded_inst_zero(&xedd);
            xed_decoded_inst_set_mode(&xedd, decoder->mmode, decoder->stack_addr_width);

            inst_in_vmp = vmp_addr_in_vmp_section(decoder, vmp_run_addr);

            if (inst_in_vmp)
            {
                if (!vmp_start)
                {
                    printf("Now, we enter vmp address. %s:%d\r\n", __FILE__, __LINE__);
                    vmp_start = 1;
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

            xed_error = xed_decode(&xedd, vmp_run_addr, 15);
            if (xed_error != XED_ERROR_NONE)
            {
                printf("vmp_decoder_run() failed with (%s)xed_decode(). %s:%d\n",
                    xed_error_enum_t2str(xed_error), __FILE__, __LINE__);
                return -1;
            }

            decode_len = xed_decoded_inst_get_length(&xedd);
            if (!decode_len)
                decode_len = 1;

            (decoder->debug.dump_inst && vmp_decoder_dump_inst(decoder, &xedd, cfg_node_stack_i, vmp_run_addr, decode_len));

            if (!cur_cfg_node)
            {
                if (NULL == (cur_cfg_node = vmp_cfg_create(decoder, vmp_run_addr, 0)))
                {
                    printf("vmp_decoder_run() failed when vmp_cfg_create(). %s:%d\r\n", __FILE__, __LINE__);
                    return NULL;
                }
                vmp_stack_push(cfg_node_stack, cur_cfg_node);
            }

            //cur_cfg_node = vmp_stack_top(cfg_node_stack);
            assert(cur_cfg_node);

vmp_run_label:
            ret = x86_emu_run(decoder->emu, vmp_run_addr, decode_len, &flow_analy);

            iat_call = 0;
            // 这个分析并非时纯的静态分析，实际上他一直在运算，所以我们在碰到条件跳转时，不
            // 分析那些走不到的分支，但是我们可以先把他加入进来
            if (flow_analy->jmp_type)
            {
                //uint8_t *addr = ((flow_analy->jmp_type == X86_COND_JMP) || flow_analy->cond) ? flow_analy->true_addr : flow_analy->false_addr;
                uint8_t *addr = ((flow_analy->jmp_type == X86_COND_JMP) || flow_analy->cond || (flow_analy->jmp_type == X86_JMP)) ? flow_analy->true_addr : flow_analy->false_addr;

                if ((t_cfg_node = vmp_cfg_find(decoder, addr)))
                {
                    vmp_run_addr = flow_analy->true_addr;
                    vmp_cfg_add_edges(decoder, cur_cfg_node, t_cfg_node, flow_analy->jmp_type);
                }
                else 
                {
                    iat_call = pe_loader_addr_in_iat(decoder->pe_mod, addr);
                    t_cfg_node = vmp_cfg_create(decoder, flow_analy->true_addr, iat_call);
                    
                    vmp_cfg_add_edges(decoder, cur_cfg_node, t_cfg_node, flow_analy->jmp_type);

                    cur_cfg_node = t_cfg_node;
                    vmp_run_addr = flow_analy->true_addr;
                }

                printf("jmp handler[%s]\n\n", cur_cfg_node->name);

                if (iat_call)
                {
                    vmp_run_addr = (uint8_t *)"\xC3";
                    decode_len = 1;
                    x86_emu_set(decoder->emu, OPERAND_TYPE_REG_EAX, (uint32_t)time(NULL));
                    goto vmp_run_label;
                }
            }
            else
            {
                vmp_run_addr += decode_len;
                vmp_cfg_add_inst(cur_cfg_node, vmp_run_addr, decode_len);
            }
        }

        if (decoder->dot_graph_output)
        {
            vmp_cfg_dump(decoder, cfg_node_stack[0]);
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

    static int vmp_cfg_add_edges(struct vmp_decoder *decoder, 
        struct vmp_cfg_node *from, struct vmp_cfg_node *to, int jmp_type)
    {
        struct vmp_cfg_node_link *link = (struct vmp_cfg_node_link *)calloc(1, sizeof (link[0]));
        assert(link);

        link->node = to;
        if (jmp_type == X86_JMP)
        {
            link->next = from->jmps.list;
            from->jmps.list = link;
            from->jmps.count++;
        }
        else
        {
            link->next = from->trues.list;
            from->trues.list = link;
            from->trues.count++;
        }
        return 0;
    }


#ifdef __cplusplus
}
#endif
