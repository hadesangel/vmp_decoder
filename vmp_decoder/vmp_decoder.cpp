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

#define VMP_X86_SET_CF_BIT(eflags)          ((eflags & 0x01) = 1)

        struct x86_emu_mod *emu;
    } vmp_decoder_t;

    struct vmp_inst_list;


#define VMP_INST_TYPE_CALL              1
#define VMP_INST_TYPE_JMP               2
    typedef struct vmp_inst_list
    {
        unsigned char *addr;
        int len;

        struct {
            unsigned int len : 5;
            unsigned int type: 2;
        }bm; //bitmap

        struct {
            struct vmp_inst_list *next;
            struct vmp_inst_list *prev;
        } node;

        union
        {
            struct vmp_cfg_node *call_label;;
            struct vmp_inst_list *true_label;
        } u;

    } vmp_inst_list_t;

    struct vmp_inst_seg_list;
    typedef struct vmp_inst_seg_list
    {
        unsigned char *addr;
        int total_len;

        struct
        {
            struct vmp_inst_seg_list *next;
            struct vmp_inst_seg_list *prev;
        } node;

        struct
        {
            int counts;
            struct vmp_inst_list *list;
        } head;
    } vmp_inst_seg_list_t;

    typedef struct vmp_cfg_node
    {
        unsigned char *id;
        char name[32];

        unsigned char *return_addr;

        struct
        {
            int counts;
            struct vmp_inst_seg_list *list;
        } seg_head;

        struct
        {
            int counts;
            struct vmp_inst_list *list;
        } jmp_head;

        struct {
            unsigned already_dot_dump   : 1;
            unsigned vmp                : 16;
        } debug;
    } vmp_cfg_node_t;

#define vmp_stack_push(_st, _val)       (_st[++_st##_i] = _val)
#define vmp_stack_is_empty(_st)         (_st##_i == -1)
#define vmp_stack_pop(_st)               (vmp_stack_is_empty(_st) ? NULL:_st[_st##_i--])
#define vmp_stack_top(_st)              (vmp_stack_is_empty(_st) ?  NULL:_st[_st##_i])

    static int vmp_addr_in_vmp_section(struct vmp_decoder *decoder, unsigned char *addr);
    static struct vmp_inst_list * vmp_jmp_enquque(struct vmp_cfg_node *node, unsigned char *addr, int len);
    static struct vmp_inst_list * vmp_find_inst_in_cfg(struct vmp_cfg_node *node, unsigned char *addr);
#define vmp_sym_addr(_decoder, _address)  (UINT64)(pe_loader_fa2rva(_decoder->pe_mod, (DWORD64)_address))

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
            //printf("Entry Point = 0x%08x\n", vmp_start_rva);
        }
        mod->vmp_start_va = vmp_start_rva;
        strcpy_s(mod->filename, filename);

        mod->image_base = (unsigned char *)mod->pe_mod->image_base;
        mod->addr_start = ((unsigned char *)mod->image_base + pe_loader_rva2rfa(mod->pe_mod, vmp_start_rva));

        //printf("image_base = %p, addr_start = %p\n", mod->image_base, mod->addr_start);

        mod->runtime_vaddr = mod->addr_start;

        xed_tables_init();
        mod->mmode = XED_MACHINE_MODE_LEGACY_32;
        mod->stack_addr_width = XED_ADDRESS_WIDTH_32b;

        mod->format_options.hex_address_before_symbolic_name = 1;
        mod->format_options.write_mask_curly_k0 = 1;
        mod->format_options.lowercase_hex = 1;

        mod->debug.dump_inst = 1;
        mod->debug.hlp = vmp_hlp_create(mod->pe_mod, filename, mod->pe_mod->file_handl, (char *)mod->pe_mod->image_base);

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

        mod->emu = x86_emu_create(32);

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
        ret = vmp_hlp_get_symbol2(decoder->debug.hlp, address, sym_buf, buf_size, offset);
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

    struct vmp_cfg_node *vmp_cfg_node_create (struct vmp_decoder *decoder, unsigned char *addr)
    {
        struct vmp_cfg_node *node = NULL;

        node = (struct vmp_cfg_node *)calloc(1, sizeof (node[0]));
        if (NULL == node)
        {
            printf("vmp_decoder_cfg_node_create() failed with calloc()");
            return NULL;
        }

        sprintf(node->name, "label%d", ++decoder->label_counts);
        node->id = addr;

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

    struct vmp_inst_list *vmp_cfg_node_add_inst(struct vmp_cfg_node *cfg_node, unsigned char *inst_addr, int inst_len)
    {
        struct vmp_inst_seg_list *seg_list;
        struct vmp_inst_list *inst_list, *last_inst;
        int i = 0;

        if ((inst_list = vmp_find_inst_in_cfg(cfg_node, inst_addr)))
        {
            return inst_list;
        }

        for (i = 0, seg_list = cfg_node->seg_head.list; i < cfg_node->seg_head.counts; i++, seg_list = seg_list->node.next)
        {
            if (!seg_list->head.counts)
                continue;

            last_inst = seg_list->head.list->node.prev;

            if ((last_inst->addr + last_inst->len) == inst_addr)
                break;
        }

        if (i == cfg_node->seg_head.counts)
        {
            seg_list = (struct vmp_inst_seg_list *)calloc(1, sizeof (seg_list[0]));
            if (!seg_list)
            {
                printf("vmp_cfg_node_add_inst() failed when calloc()");
                return NULL;
            }
            mlist_add(cfg_node->seg_head, seg_list, node);
        }

        inst_list = (struct vmp_inst_list *)calloc(1, sizeof (inst_list[0]));
        if (!inst_list)
        {
            printf("vmp_cfg_node_add_inst() failed when calloc()");
            return NULL;
        }

        inst_list->addr = inst_addr;
        inst_list->len = inst_len;
        seg_list->total_len += inst_len;

        mlist_add(seg_list->head, inst_list, node);

        if (!seg_list->addr)
        {
            seg_list->addr = inst_addr;
        }

        return inst_list;
    }

    int vmp_cfg_node__dump(struct vmp_decoder *decoder, struct vmp_cfg_node *node)
    {
        struct vmp_inst_list *list;
        struct vmp_inst_seg_list *seg_list;
        //xed_decoded_inst_t xedd;
        //xed_error_enum_t xed_error;
        //char buf[64];
        char sym1[128], sym2[128];
        int i, j;

        if (node->debug.already_dot_dump)
            return 0;

        node->debug.already_dot_dump = 1;

        if (!vmp_hlp_get_symbol(decoder->debug.hlp, vmp_sym_addr(decoder, node->id), sym1, sizeof (sym1), NULL))
        {
            sprintf(sym1, "%s", node->name);
        }
        //printf("symname = %s, 0x%p\n", sym1, node->id);

        fprintf(decoder->dot_graph_output, " %s [label=%s", sym1, sym1);

#if 0
        for (i = 0, list = node->inst_head.list; i < node->inst_head.counts; i++, list = list->node.next)
        {
            xed_decoded_inst_zero(&xedd);
            xed_decoded_inst_set_mode(&xedd, decoder->mmode, decoder->stack_addr_width);

            xed_error = xed_decode(&xedd, list->addr, list->len);
            if (xed_error != XED_ERROR_NONE)
            {
                printf("vmp_cfg_node__dump() failed when xed_decode()");
                return -1;
            }
            vmp_decoder_dump_inst(decoder, &xedd, (xed_uint64_t)list->addr, buf, sizeof (buf) -1);
            fprintf(decoder->dot_graph_output, "%s\\n", buf);
        }
#endif
        fprintf(decoder->dot_graph_output, "];\n");

        for (i = 0, seg_list = node->seg_head.list; i < node->seg_head.counts; i++, seg_list = seg_list->node.next)
        {
            for (j = 0, list = seg_list->head.list; j < seg_list->head.counts; j++, list = list->node.next)
            {
                if (list->bm.type == VMP_INST_TYPE_CALL)
                {
                    vmp_cfg_node__dump(decoder, list->u.call_label);
                }
            }
        }

        for (i = 0, seg_list = node->seg_head.list; i < node->seg_head.counts; i++, seg_list = seg_list->node.next)
        {
            for (j = 0, list = seg_list->head.list; j < seg_list->head.counts; j++, list = list->node.next)
            {
                if (list->bm.type == VMP_INST_TYPE_CALL)
                {
                    if (!vmp_hlp_get_symbol(decoder->debug.hlp, vmp_sym_addr(decoder, list->u.call_label->id), sym2, sizeof(sym2), NULL))
                    {
                        sprintf(sym2, "%s", list->u.call_label->name);
                    }

                    fprintf(decoder->dot_graph_output, "%s -> %s;\n", sym1, sym2);
                }
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
        int  num_of_inst = 2000, inst_in_vmp;
        xed_error_enum_t xed_error;
        xed_decoded_inst_t xedd;
        int decode_len, ok = 0, i, j, is_break;
        struct vmp_cfg_node *cfg_node_stack[128];
        int cfg_node_stack_i = -1, is_end = 0, offset, addr;
        struct vmp_cfg_node *cur_cfg_node = NULL, *t_cfg_node;
        struct vmp_inst_list *cur_inst, *t_inst;
        char buf[64];
        unsigned char *new_addr;
        static int vmp_start = 0;

        if (!decoder->dot_graph_output)
        {
            decoder->dot_graph_output = fopen("1.dot", "w");
        }

        for (i = 0; i < num_of_inst; i++, inst_in_vmp = 0)
        {
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
                    //printf("vmp [%d]\n", decoder->vmp_sections.call_counts);
                    vmp_cfg_node_update_vmp(cur_cfg_node, ++decoder->vmp_sections.call_counts);
                    //printf("vmp name[%s]\n", cur_cfg_node->name);
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
                printf("[%p]", decoder->runtime_vaddr);
                for (j = 0; j < cfg_node_stack_i; j++)
                {
                    printf("    ");
                }
                for (j = 0; j < decode_len; j++)
                {
                    printf ("%02x ", decoder->runtime_vaddr[j]);
                }
                for (j = decode_len; j < 16; j++)
                {
                    printf("   ");
                }
                vmp_decoder_dump_inst(decoder, &xedd, (xed_uint64_t)decoder->runtime_vaddr, buf, sizeof (buf) -1);
                printf("[%s]\n", buf);
            }
            if (!cur_cfg_node)
            {
                if (NULL == (cur_cfg_node = vmp_cfg_node_create(decoder, decoder->runtime_vaddr)))
                {
                    printf("vmp_decoder_run() failed when vmp_cfg_node_create(). %s:%d\r\n", __FILE__, __LINE__);
                    return NULL;
                }
                vmp_stack_push(cfg_node_stack, cur_cfg_node);
            }

            cur_cfg_node = vmp_stack_top(cfg_node_stack);
            assert(cur_cfg_node);

            //printf("stack  height = %d\n", cfg_node_stack_i + 1);
            cur_inst = vmp_cfg_node_add_inst(cur_cfg_node, decoder->runtime_vaddr, decode_len);

            switch (decoder->runtime_vaddr[0])
            {
                    // jz
                case 0x74:
                    // jnz
                case 0x75:
                    // jl
                case 0x7c:
                    // near jmp
                case 0xeb:
                    offset = decoder->runtime_vaddr[1];
                    new_addr = decoder->runtime_vaddr + offset + decode_len;

                    cur_inst->bm.type = VMP_INST_TYPE_JMP;

                    if ((t_inst = vmp_find_inst_in_cfg (cur_cfg_node, new_addr)))
                    {
                        cur_inst->u.true_label = t_inst;
                    }
                    else
                    {
                        //printf("enqueu addr %p , %p, %s:%d\n", cur_cfg_node, new_addr, __FILE__, __LINE__);
                        vmp_jmp_enquque(cur_cfg_node, new_addr, decode_len);
                    }

                    decoder->runtime_vaddr += decode_len;
                    break;

                    // call
                case 0xe8:
                    cur_cfg_node->return_addr = decoder->runtime_vaddr + decode_len;

                    offset = mbytes_read_int_little_endian_4b(decoder->runtime_vaddr + 1);
                    decoder->runtime_vaddr += offset + decode_len;
                    //printf("cur[0x%p] add[0x%x] new addr = %p\n", cur_cfg_node, offset, decoder->runtime_vaddr );
                    t_cfg_node = vmp_cfg_node_create(decoder, decoder->runtime_vaddr);
                    if (!t_cfg_node)
                    {
                        printf("vmp_decoder_run() failed when vmp_cfg_node_create()");
                        return -1;
                    }
                    vmp_stack_push(cfg_node_stack, t_cfg_node);
                    cur_inst->bm.type = VMP_INST_TYPE_CALL;
                    cur_inst->u.call_label = t_cfg_node;
                    break;

                    // jmp
                case 0xe9:
                    offset = mbytes_read_int_little_endian_4b(decoder->runtime_vaddr + 1);
                    new_addr = (unsigned char *)pe_loader_fa_fix(decoder->pe_mod, (DWORD64)decoder->runtime_vaddr, offset + decode_len);
                    if (!new_addr)
                    {
                        printf("vmp_decoder_run() meet un-support jmp offset \n. %s:%d\r\n", __FILE__, __LINE__);
                        decoder->runtime_vaddr += decode_len;
                        break;
                    }

#if 0
                    // consider as a function
                    if (new_addr < cur_cfg_node->id)
                    {
                        decoder->runtime_vaddr = new_addr;
                        t_cfg_node = vmp_cfg_node_create(decoder, decoder->runtime_vaddr);
                        if (!t_cfg_node)
                        {
                            printf("vmp_decoder_run() failed when vmp_cfg_node_create()");
                            return -1;
                        }
                        vmp_stack_push(cfg_node_stack, t_cfg_node);
                        cur_inst->bm.type = VMP_INST_TYPE_CALL;
                        cur_inst->u.call_label = t_cfg_node;
                        cur_cjg_node->return_addr = 0;
                    }
                    else
                    { // consider as a jump label
                        decoder->runtime_vaddr = new_addr;
                        //goto label_inner_jmp;
                    }
#endif

                    decoder->runtime_vaddr = new_addr;
                    break;

                case 0xf2:
                    if (decoder->runtime_vaddr[1] != 0xc3)
                    {
                        decoder->runtime_vaddr += decode_len;
                        break;
                    }
                    // ret
                case 0xC3:
                    label_asm_ret:
                    // iteration jmp list, check all branch
                    is_break = 0;
                    while (cur_cfg_node->jmp_head.list && !is_break)
                    {
                        t_inst = cur_cfg_node->jmp_head.list;
                        mlist_del(cur_cfg_node->jmp_head, t_inst, node);

                        //printf("find addr %p = %p, %s:%d\n", cur_cfg_node, t_inst->addr, __FILE__, __LINE__);
                        if (!vmp_find_inst_in_cfg (cur_cfg_node, t_inst->addr))
                        {
                            decoder->runtime_vaddr = t_inst->addr;
                            is_break = 1;
                        }

                        free(t_inst);
                    }

                    if (is_break)
                        break;

                    // pop stack, goto older called function
                    cur_cfg_node = vmp_stack_pop(cfg_node_stack);
                    if (NULL == cur_cfg_node)
                    {
                        printf("vmp_decoder_run() failed with un-expected error, stack downflow \n");
                        return -1;
                    }
                    //printf("after pop height = %d\n", cfg_node_stack_i + 1);

                    if (vmp_stack_is_empty(cfg_node_stack))
                    {
                        printf("****vmp_decoder_run() meet end***");
                        is_end = 1;
                        break;
                    }
                    cur_cfg_node = vmp_stack_top(cfg_node_stack);
                    decoder->runtime_vaddr = cur_cfg_node->return_addr;
                    if (!decoder->runtime_vaddr && (vmp_stack_is_empty (cfg_node_stack)))
                    {
                        printf("****vmp_decoder_run() meet end***");
                        is_end = 1;
                        break;
                    }
                    //printf("cur_cfg_node[%d:0x%p] return back[0x%p]. %s:%d\r\n", cfg_node_stack_i, cur_cfg_node, decoder->runtime_vaddr, __FILE__, __LINE__);
                    break;

                    // IAT jump, call
                case 0xff:
                    if (decoder->runtime_vaddr[1] == 0x15)
                    {
                        addr = mbytes_read_int_little_endian_4b(decoder->runtime_vaddr + 2);

                        if (0 == pe_loader_sym_find (decoder->pe_mod, addr, buf, sizeof(buf)))
                        {
                            // printf("symbol [%s]\n", buf);
                        }
                    }
                    else if (decoder->runtime_vaddr[1] == 0x25)
                    {
                        goto label_asm_ret;
                    }

                    decoder->runtime_vaddr += decode_len;
                    break;

                default:
                    if (inst_in_vmp)
                    {
                        x86_emu_run(decoder->emu, decoder->runtime_vaddr, decode_len);
                    }
                    decoder->runtime_vaddr += decode_len;
                    break;
            }

            if (is_end)
                break;
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

    static struct vmp_inst_list * vmp_find_inst_in_cfg(struct vmp_cfg_node *node, unsigned char *addr)
    {
        int i, j;
        struct vmp_inst_seg_list *seg_list;
        struct vmp_inst_list *list;

        for (i = 0, seg_list = node->seg_head.list; i < node->seg_head.counts; i++, seg_list = seg_list->node.next)
        {
            if ((addr < seg_list->addr) || (addr >= (seg_list->addr + seg_list->total_len)))
            {
                continue;
            }

            for (j = 0, list = seg_list->head.list; j < seg_list->head.counts; j++, list = list->node.next)
            {
                if ((addr >= list->addr) && (addr < (list->addr + list->len)))
                {
                    return list;
                }
            }
        }

        return NULL;
    }

    static struct vmp_inst_list * vmp_jmp_enquque(struct vmp_cfg_node *node, unsigned char *addr, int len)
    {
        struct vmp_inst_list *list;

        list = (struct vmp_inst_list *)calloc(1, sizeof (list[0]));
        if (NULL == list)
        {
            printf("vmp_jmp_enqueu() failed with calloc(). %s:%d\r\n", __FILE__, __LINE__);
            return NULL;
        }

        list->addr = addr;
        list->len = len;

        mlist_add(node->jmp_head, list, node);

        return list;
    }


#ifdef __cplusplus
}
#endif
