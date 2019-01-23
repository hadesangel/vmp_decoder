
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "x86_emu.h"
#include "mbytes.h"

static int x86_emu_modrm_analysis(uint8_t modrm, int *dst_type, int *src_type);
static struct x86_emu_reg *x86_emu_reg_get(struct x86_emu_mod *mod, int reg_type);
static int x86_emu_modrm_analysis2(struct x86_emu_mod *mod, uint8_t *cur, int oper_size1, int *dst_type, int *src_type, struct x86_emu_reg *imm);

static int x86_emu_cf_set(struct x86_emu_mod *mod, int v);
static int x86_emu_cf_get(struct x86_emu_mod *mod);
static int x86_emu__push_reg(struct x86_emu_mod *mod, int oper_siz1, struct x86_emu_reg *reg);
static int x86_emu__push_imm8(struct x86_emu_mod *mod, uint8_t imm8);
static int x86_emu__push_imm16(struct x86_emu_mod *mod, uint8_t imm8);
static int x86_emu__push_imm32(struct x86_emu_mod *mod, uint8_t imm8);

int x86_emu_add(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_lea(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_mov(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_xor(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_bt(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_bts(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_btc(struct x86_emu_mod *mod, uint8_t *code, int len);
static uint32_t x86_emu_reg_val_get(int oper_siz, struct x86_emu_reg *reg);

#define X86_EMU_REG_IS_KNOWN(_op_siz, _reg)                 (((_op_siz == 32) && ((_reg)->known == 0xffffffff)) || ((_op_siz == 16) && ((_reg)->known == 0xffff)))
#define X86_EMU_REG_BIT_IS_KNOWN(_op_siz, _reg, _bit_pos)   ((_reg)->known & (1 << (_bit_pos % _op_siz)))
#define X86_EMU_EFLAGS_BIT_IS_KNOWN(_bit)                   ((_bit) >= 0)

#define MODRM_GET_MOD(_c)   ((_c) >> 6)
#define MODRM_GET_RM(_c)    ((_c) & 3)
#define MODRM_GET_REG(_c)   (((_c) >> 2) & 3)

#define x86_emu_dynam_imm_set(_dst_reg1, _code) \
    do { \
        if (mod->inst.oper_size == 16) \
        {  \
            (_dst_reg1)->known |= 0xffff; \
            (_dst_reg1)->u.r16 = mbytes_read_int_little_endian_2b(_code); \
        } \
        else if (mod->inst.oper_size == 32) \
        { \
            (_dst_reg1)->known |= 0xffffffff; \
            (_dst_reg1)->u.r32 = mbytes_read_int_little_endian_4b(_code); \
        } \
    } while (0)

#define x86_emu_dynam_set(_dst_reg1, _imm) \
    do \
    { \
        if (mod->inst.oper_size == 16) \
        { \
            (_dst_reg1)->known |= 0xffff; \
            (_dst_reg1)->u.r16 = (uint16_t)_imm; \
        } \
        else if (mod->inst.oper_size == 32) \
        { \
            (_dst_reg1)->known |= 0xffffffff; \
            (_dst_reg1)->u.r32  = (uint32_t)_imm; \
        } \
    } while (0)

#define x86_emu_dynam_bit_set(_dst_reg1, _bit_pos) \
    do \
    { \
        if (mod->inst.oper_size == 16) \
        { \
            (_dst_reg1)->known |= (1 << (_bit_pos )); \
            (_dst_reg1)->u.r16 |= (1 << (_bit_pos % 16)); \
        } \
        else if (mod->inst.oper_size == 32) \
        { \
            (_dst_reg1)->known |= (1 << (_bit_pos % 32)); \
            (_dst_reg1)->u.r32  = (1 << (_bit_pos % 32)); \
        } \
    } while (0)

#define x86_emu_dynam_bit_clear(_dst_reg1, _bit_pos) \
    do \
    { \
        if (mod->inst.oper_size == 16) \
        { \
            (_dst_reg1)->known |= (1 << (_bit_pos )); \
            (_dst_reg1)->u.r16 &= ~(1 << (_bit_pos % 16)); \
        } \
        else if (mod->inst.oper_size == 32) \
        { \
            (_dst_reg1)->known |= (1 << (_bit_pos % 32)); \
            (_dst_reg1)->u.r32  &= ~(1 << (_bit_pos % 32)); \
        } \
    } while (0)



#define x86_emu_dynam_oper(_dst_reg1, _oper, _src_reg1) \
    do \
    { \
        if (mod->inst.oper_size == 16) \
        { \
            (_dst_reg1)->u.r16 _oper (_src_reg1)->u.r16; \
        } \
        else if (mod->inst.oper_size == 32) \
        { \
            (_dst_reg1)->u.r32 _oper (_src_reg1)->u.r32; \
        } \
    } while (0)


#define X86_EMU_OPER_SET            1
#define X86_EMU_OPER_MOVE           X86_EMU_OPER_MOVE
#define X86_EMU_OPER_ADD            2
#define X86_EMU_OPER_NOT            3
#define X86_EMU_OPER_XOR            4

#define counts_of_array(_a)         (sizeof (_a) / sizeof (_a[0]))

struct x86_emu_mod *x86_emu_create(int word_size)
{
    struct x86_emu_mod *mod;

    mod = (struct x86_emu_mod *)calloc(1, sizeof (mod[0]));
    if (!mod)
    {
        printf("x86_emu_create() failed when calloc(). %s:%d", __FILE__, __LINE__);
        return NULL;
    }

    mod->eax.type = OPERAND_TYPE_REG_EAX;
    mod->ebx.type = OPERAND_TYPE_REG_EBX;
    mod->ecx.type = OPERAND_TYPE_REG_ECX;
    mod->edx.type = OPERAND_TYPE_REG_EDX;
    mod->edi.type = OPERAND_TYPE_REG_EDI;
    mod->esi.type = OPERAND_TYPE_REG_ESI;
    mod->ebp.type = OPERAND_TYPE_REG_EBP;
    mod->esp.type = OPERAND_TYPE_REG_ESP;

    return mod;
}

int x86_emu_destroy(struct x86_emu_mod *mod)
{
    if (mod)
    {
        free(mod);
    }

    return 0;
}

int x86_emu_push(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *reg;
    switch (code[0])
    {
    case 0x52:
        break;
        // push ebp
    case 0x55:
        reg = x86_emu_reg_get(mod, OPERAND_TYPE_REG_EBP);
        break;
    }
    return 0;
}

int x86_emu_push_reg(struct x86_emu_mod *mod, int reg_type)
{
    x86_emu_reg_t *reg = x86_emu_reg_get(mod, reg_type);

    if (!reg)
    {
        printf("x86_emu_push_reg(%p, %d) failed with invalid param. %s:%d", mod, reg_type, __FILE__, __LINE__);
        return -1;
    }

    return 0;
}

int x86_emu_push_imm(struct x86_emu_mod *mod, int val)
{
    return 0;
}

int x86_emu_push_eflags (struct x86_emu_mod *mod)
{
    return 0;
}

// 右移指令的操作数不止是寄存器，但是这个版本中，先只处理寄存器
int x86_emu_shrd (struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int dst_type, src_type, cts;
    struct x86_emu_reg src_imm, *dst_reg, *src_reg;

    switch (code[0])
    { 
    case 0xac:
        x86_emu_modrm_analysis2(mod, code, 0, &src_type, &dst_type, &src_imm);
        dst_reg = x86_emu_reg_get(mod, dst_type);;
        src_reg = x86_emu_reg_get(mod, src_type);
        cts = code[2] & 0x1f;

        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, dst_reg) && X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, src_reg))
        {
            if (mod->inst.oper_size == 32)
            {
                dst_reg->u.r32 >>= cts;
                dst_reg->u.r32 |= (src_reg->u.r32 << (mod->inst.oper_size - cts));
            }
            else if (mod->inst.oper_size == 16)
            { 
                dst_reg->u.r16 >>= cts;
                dst_reg->u.r16 |= (src_reg->u.r16 << (mod->inst.oper_size - cts));
            }
        }
        break;
    }
    return 0;
}

int x86_emu_shl(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    return 0;
}

#define BIT_TEST    0
#define BIT_SET     1
#define BIT_CLEAR   2
int x86_emu_bt_oper(struct x86_emu_mod *mod, uint8_t *code, int len, int oper)
{
    int dst_type, src_type; 
    struct x86_emu_reg src_imm = {0}, *dst_reg;
    uint32_t src_val, dst_val;

    x86_emu_modrm_analysis2(mod, code, 0, &dst_type, &src_type, &src_imm);

    dst_reg = x86_emu_reg_get (mod, dst_type);
    /* 源操作数已知的情况下，只要目的操作的src位bit是静态可取的，那么就可以计算的 */
    if (X86_EMU_REG_IS_KNOWN (mod->inst.oper_size, &src_imm)
        && (1 | (src_val = x86_emu_reg_val_get(mod->inst.oper_size, &src_imm)))
        && X86_EMU_REG_BIT_IS_KNOWN(mod->inst.oper_size, dst_reg, src_val))
    {
        dst_val = x86_emu_reg_val_get(mod->inst.oper_size, dst_reg);
        src_val %= mod->inst.oper_size;

        x86_emu_cf_set(mod, dst_val & src_val);

        switch (oper)
        {
        case BIT_SET:
            x86_emu_dynam_bit_set(dst_reg, src_val);
            break;

        case BIT_CLEAR:
            x86_emu_dynam_bit_clear(dst_reg, src_val);
            break;
        }
    }

    return 0;
}

int x86_emu_bt(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    // skip 0x0f
    code++;
    len--;

    switch (code[0])
    {
    case 0xba:
        x86_emu_bt_oper(mod, code + 1, len - 1, BIT_TEST);
        break;
    }

    return 0;
}

int x86_emu_bts(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    // 跳过0x0f
    code++;
    len--;

    switch (code[0])
    {
    case 0xab:
        x86_emu_bt_oper(mod, code + 1, len --, BIT_SET);
        break;
    }
    return 0;
}

int x86_emu_btc(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    // skip 0x0f
    code++;
    len--;

    switch (code[0])
    {
    case 0xbb:
        x86_emu_bt_oper(mod, code + 1, len - 1, BIT_CLEAR);
        break;
    }

    return 0;
}

int x86_emu_xor(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *src_reg, *dst_reg, src_imm = {0};
    int dst_type, src_type;

    x86_emu_modrm_analysis2(mod, code + 1, 0, &dst_type, &src_type, &src_imm);
    dst_reg = x86_emu_reg_get(mod, dst_type);
    src_reg = x86_emu_reg_get(mod, src_type);

    switch (code[0])
    {
    case 0x33:
        if (src_type == dst_type)
            x86_emu_dynam_set(dst_reg, 0);
        else
            x86_emu_dynam_oper(dst_reg, ^= , src_reg);

        break;

    case 0x81:
        x86_emu_dynam_oper(dst_reg, ^=, &src_imm);
        break;
    }

    return 0;
}

int x86_emu_lea(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int dst_type = 0, src_type = 0;
    x86_emu_reg_t *dst_reg, src_imm;

    switch (code[0])
    {
    case 0x8d:
        x86_emu_modrm_analysis2(mod, code + 1, 0, &dst_type, &src_type, &src_imm);
        dst_reg = x86_emu_reg_get(mod, dst_type);
        X86_EMU_REG_SET_r32(dst_reg, src_imm.u.r32);

        break;
    }
    return 0;
}

int x86_emu_mov(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int dst_type = 0, src_type = 0;
    struct x86_emu_reg *dst_reg = NULL;

    switch (code[0])
    { 
        //这个指令不知道为什么在intel-2b上搜不到
    case 0xbd:
        dst_reg = x86_emu_reg_get(mod, OPERAND_TYPE_REG_EBP);
        x86_emu_dynam_imm_set(dst_reg, code + 1);
        break;
    }

    return 0;
}

int x86_emu_add(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int dst_type = 0, src_type = 0;
    x86_emu_reg_t *dst_reg, src_imm;

    switch (code[0])
    {
    case 0x03:
        x86_emu_modrm_analysis2(mod, code + 1, 0, &dst_type, &src_type, &src_imm);
        dst_reg = x86_emu_reg_get(mod, dst_type);

        if (mod->inst.oper_size == 16)
        {
            dst_reg->u.r16 += src_imm.u.r16;
        }
        else if (mod->inst.oper_size == 32)
        {
            dst_reg->u.r32 += src_imm.u.r32;
        }
        break;
    }
    return 0;
}

int x86_emu_and(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int dst_type, src_type;
    struct x86_emu_reg src_imm = {0}, *dst_reg;

    switch (code[0])
    {
    case 0x81:
        x86_emu_modrm_analysis2(mod, code + 1, 0, &dst_type, &src_type, &src_imm);
        dst_reg = x86_emu_reg_get(mod, dst_type);
        x86_emu_dynam_oper(dst_reg, &=, &src_imm);
        break;
    }

    return 0;
}

int x86_emu_or(struct x86_emu_mod *mod, uint8_t *addr, int len)
{
    return 0;
}


int x86_emu_alu_add(struct x86_emu_mod *mod, uint32_t dst, uint32_t src)
{
    int oper_siz = mod->inst.oper_size;

    int sign_src = src & (1 << (oper_siz - 1)), sign_dst = dst & (1 << (oper_siz - 1)), sign_s;

    uint32_t s = dst + src;

    uint32_t c = (s ^ dst ^ src) & 0x00010000;
   
    s = s - c;

    sign_s = (1 << (oper_siz - 1));

    x86_emu_cf_set(mod, c);

    if ((sign_src == sign_dst) && (sign_s != sign_src))
    {
        x86_emu_of_set(mod, 1);
    }

    if (src == dst)
    {
        x86_emu_zf_set(mod, 1);
    }

    x86_emu_sf_set(mod, !!sign_s);

    return 0;
}

int x86_emu_adc(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int dst_type, src_type, ret;
    struct x86_emu_reg *dst_reg, *src_reg, src_imm = {0};

    switch(code[0])
    {
    case 0x13:
        x86_emu_modrm_analysis2(mod, code, 0, &dst_type, &src_type, &src_imm);
        dst_reg = x86_emu_reg_get(mod, dst_type);
        src_reg = x86_emu_reg_get(mod, src_type);
        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, dst_reg)
            && X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, src_reg)
            && X86_EMU_EFLAGS_BIT_IS_KNOWN((ret = x86_emu_cf_get(mod))))
        {
            if (mod->inst.oper_size == 32)
            {
                dst_reg->u.r32 += src_reg->u.r32 + ret;
            }
            else if (mod->inst.oper_size == 16)
            {
                dst_reg->u.r16 += src_reg->u.r16 + ret;
            }
        }
            
        break;
    }
    return 0;
}

int x86_emu_sbb(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int dst_type, src_type, cf;
    struct x86_emu_reg src_imm = { 0 }, *dst_reg, *src_reg;
    switch (code[0])
    {
    case 0x1b:
        x86_emu_modrm_analysis2(mod, code, 0, &dst_type, &src_type, &src_imm);
        dst_reg = x86_emu_reg_get(mod, dst_type);

        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, dst_reg)
            && X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, src_reg)
            && X86_EMU_EFLAGS_BIT_IS_KNOWN(cf = x86_emu_cf_get(mod)))
        {
            // todo:这个地方需要更加细致的处理所有标志位的影响，但是我还没考虑清楚，
            // 所以暂时没做改动
            if (mod->inst.oper_size == 32)
            {
                dst_reg->u.r32 -= src_imm.u.r32 + cf;
            }
            else if (mod->inst.oper_size == 16)
            { 
                dst_reg->u.r16 -= src_imm.u.r16 + cf;
            }
        }
        break;
    }
    return 0;
}

int x86_emu_sub(struct x86_emu_mod *mod, uint8_t *addr, int len)
{
    return 0;
}

int x86_emu_cmp(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int dst_type, src_type;
    x86_emu_reg_t *dst_reg, *src_reg;

    switch (code[0])
    {
    case 0x3b:
        x86_emu_modrm_analysis2(mod, code, 0, &dst_type, &src_type, NULL);
        dst_reg = x86_emu_reg_get(mod, dst_type);
        src_reg = x86_emu_reg_get(mod, src_type);

        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, dst_reg)
            && X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, src_reg))
        {
        }
        break;
    }
    return 0;
}

int x86_emu_not(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int dst_type, src_type;
    x86_emu_reg_t *dst_reg, *src_reg, src_imm = {0};
    switch (code[0])
    {
    case 0xf7:
        x86_emu_modrm_analysis2(mod, code, 0, &dst_type, &src_type, &src_imm);
        dst_reg = x86_emu_reg_get(mod, &dst_type);
        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, dst_reg))
        {
            // 这个函数调用的不怎么和规范， 实际上是利用了字符串的拼接规则对寄存器取反了
            // 后面的~，实际上不是=的一部分，而是dst_reg的一部分，~dst_reg
            x86_emu_dynam_oper(dst_reg, =~, dst_reg);
        }

        break;

    default:
        assert(0);
        break;
    }

    return 0;
}


static inline int x86_emu_inst_init(struct x86_emu_mod *mod, uint8_t *inst, int len)
{
    mod->inst.oper_size = 32;
    mod->inst.start = inst;
    mod->inst.len = len;

    return 0;
}

struct x86_emu_on_inst_item x86_emu_inst_tab[] = 
{
    { 0x1b, -1, x86_emu_sbb },
    { 0x03, -1, x86_emu_add },
    { 0x33, -1, x86_emu_xor },
    { 0x81, 0, x86_emu_add },
    { 0x81, 1, x86_emu_or },
    { 0x81, 2, x86_emu_adc },
    { 0x81, 3, x86_emu_sbb },
    { 0x81, 4, x86_emu_and },
    { 0x81, 5, x86_emu_sub },
    { 0x81, 6, x86_emu_xor },
    { 0x81, 7, x86_emu_cmp },
    { 0x8d, -1, x86_emu_lea },
    { 0xbd, -1, x86_emu_mov },
    { 0xf7, 2, x86_emu_not },
};

struct x86_emu_on_inst_item x86_emu_inst_tab2[] =
{
    { 0xab, -1, x86_emu_bts },
    { 0xac, -1, x86_emu_shrd },
    { 0xba, -1, x86_emu_bt },
    { 0xbb, -1, x86_emu_btc },
    { 0, -1, NULL},
};


int x86_emu_run(struct x86_emu_mod *mod, uint8_t *addr, int len)
{
    uint32_t i32;
    uint16_t i16;

    x86_emu_inst_init(mod, addr, len);
    int i, code_i = 1;
    // x86模拟器的主循环需要对指令集比较深厚的理解
    // 英文注释直接超自白皮书，这样可以减少查询的工作量，大家可以放心观看
    // 中文注释来自于作者

    // Instruction prefixes are divided into four groups, each with a set of allowable prefix codex. 
    // For each instruction, it is only useful to include up to one prefix code from each of the four
    // groups (Groups 1, 2, 3, 4).
    switch (addr[0])
    {
        // operand-size override prefix is encoded using 66H.
        // The operand-size override prefix allows a program to switch between 16- and 32- bit operand size.
    case 0x66:
        mod->inst.oper_size = 16;
        break;

    case 0x67:
        break;

        // lock
    case 0xf0:
        break;

        // REPNE/REPNZ 
        // Bound prefix is encoded using F2H if the following conditions are true:
        // CPUID. (EAX = 07H, ECX = 0)
        // refer to: ia32-2a.pdf
    case 0xf2:
        break;

        // REP/REPE/REPX
    case 0xf3:
        break;

    default:
        code_i = 0;
        break;
    }

    switch (addr[code_i])
    {
        // push edx
    case 0x52:
        x86_emu_push_reg(mod, OPERAND_TYPE_REG_EDX);
        break;

        // push ebp
    case 0x55:
        x86_emu_push_reg(mod, OPERAND_TYPE_REG_EBP);
        break;

    // mov bp
    case 0xbd:
        i16 = mbytes_read_int_little_endian_2b(addr + 2);
        //decoder->x86_emulator.ebp = i16;
        break;

    case 0x0f:
        switch (addr[code_i+1])
        { 
            // bt
        case 0xba:
            // 0x0f 0xba是不定长指令，这个地方，我们应该去处理ModR/M格式的数据但是这里为了简化处理，
            // 我们直接判断这个值了，因为看起来vmp生成的格式数据就这么几个套路
            if (addr[code_i+2] == 0xe5)
            {
                if (addr[code_i + 3] > 32)
                {
                    X86_EMU_REG_SET_r32(&mod->ebp, 0);
                }
            }
            break;

        default:
            for (i = 0; i < counts_of_array(x86_emu_inst_tab2); i++)
            {
                if (x86_emu_inst_tab2[i].type == addr[code_i])
                {
                    x86_emu_inst_tab2[i].on_inst(mod, addr + code_i, len - code_i);
                }
            }

            if (i == counts_of_array(x86_emu_inst_tab2))
            {
                printf("vmp_x86_emulator() meet unknow instruct. %s:%d\r\n", __FILE__, __LINE__);
            }
            break;
        }
        break;

        // push i32
    case 0x68:
        i32 = mbytes_read_int_little_endian_4b(addr + 1);
        x86_emu_push_imm(mod, i32);
        break;

        // pushfd
    case 0x9c:
        x86_emu_push_eflags(mod);
        break;

    default:
        for (i = 0; i < counts_of_array(x86_emu_inst_tab); i++)
        {
            if (x86_emu_inst_tab[i].type != addr[code_i])
                continue;

            if ((x86_emu_inst_tab[i].reg != -1))
            {
                if (MODRM_GET_REG(addr[code_i + 1]) == x86_emu_inst_tab[i].reg)
                {
                    x86_emu_inst_tab[i].on_inst(mod, addr + code_i, len - code_i);
                }
            }
            else
            { 
                x86_emu_inst_tab[i].on_inst(mod, addr + code_i, len - code_i);
            }
        }

        if (i == counts_of_array(x86_emu_inst_tab))
        {
            printf("vmp_x86_emulator() meet unknow instruct. %s:%d\r\n", __FILE__, __LINE__);
        }
    }
    return 0;
}

// private function

// refer from vol-2a

static int modrm_rm_tabl[] = {
    OPERAND_TYPE_REG_EAX, // 000
    OPERAND_TYPE_REG_ECX, // 001
    OPERAND_TYPE_REG_EDX, // 010
    OPERAND_TYPE_REG_EBX, // 011
    OPERAND_TYPE_REG_ESP, // 100 
    OPERAND_TYPE_REG_EBP, // 101
    OPERAND_TYPE_REG_ESI, // 110
    OPERAND_TYPE_REG_EDI  // 111
};

// imm是传出参数，当src计算完毕以后，会放入到imm中传出
// 当我们判断指令的操作数长度时，除了根据指令本身的长度前缀以外
// 还要判断指令本身是否有限制指令长度，比如:
// 0a da            [or dl, al]
// 0a指令本身就规定了操作数是8bit寄存器
static int x86_emu_modrm_analysis2(struct x86_emu_mod *mod, uint8_t *cur, int oper_size1, int *dst_type1, int *src_type1, struct x86_emu_reg *imm1)
{
    uint8_t modrm = cur[0];
    uint8_t v8;
    uint32_t v32;
    x86_emu_reg_t *reg, imm = {0};
    int oper_size = oper_size1 ? oper_size1 : mod->inst.oper_size, src_type, dst_type;

    int mod1 = MODRM_GET_MOD(modrm);
    int rm1 = MODRM_GET_RM(modrm);
    int reg1 = MODRM_GET_REG(modrm);

    src_type = modrm_rm_tabl[reg1];
    reg = x86_emu_reg_get(mod, src_type);
    imm = *reg;

    switch (mod1)
    {
    case 0:
        break;

        // 加立即数，不会修改寄存器中值的 known 状态
    case 1:
        v8 = cur[1];
        imm.u.r8 += v8;
        break;

    case 2:
        v32 = mbytes_read_int_little_endian_4b(cur + 1);
        imm.u.r32 += v32;
        break;

    case 3:
        dst_type = modrm_rm_tabl[rm1];
        break;
    }

    if (src_type1)      *src_type1 = src_type;
    if (dst_type1)      *dst_type1 = dst_type;
    if (imm1)           *imm1 = imm;

    return 0;
}

static int x86_emu_modrm_analysis(uint8_t modrm, int *dst_type, int *src_type)
{
    // 这里最好的是根据白皮书2a部分，生成完整的表格，为了测试，我只处理特殊情况

    int mod = modrm >> 6;
    int rm = modrm & 3;
    int reg = (modrm >> 2) & 3;


    switch (mod)
    {
    case 0:
        break;
    case 1:
        break;
    case 2:
        break;
    case 3:
        *src_type = modrm_rm_tabl[reg];
        *dst_type = modrm_rm_tabl[rm];
        break;
    }

    return 0;
}

static struct x86_emu_reg *x86_emu_reg_get(struct x86_emu_mod *mod, int reg_type)
{
    x86_emu_reg_t *regs = &mod->eax;
    int i;

    for (i = 0; i < 8; i++)
    {
        if (regs[i].type == reg_type)
        {
            return regs + i;
        }
    }

    printf("x86_emu_reg_get(, %d) meet un-support reg_type. %s:%d\r\n", reg_type, __FILE__, __LINE__);

    return NULL;
}

static int x86_emu_cf_set(struct x86_emu_mod *mod, int v)
{
    mod->eflags.cf = v;
    mod->eflags.known.cf = 1;
    return 0;
}

static int x86_emu_cf_get(struct x86_emu_mod *mod)
{
    return (mod->eflags.known.cf ? mod->eflags.cf : -1);
}

static int x86_emu_pf_set(struct x86_emu_mod *mod, int v)
{
    return 0;
}

static int x86_emu_pf_get(struct x86_emu_mdo *mod)
{
    return 0;
}

static int x86_emu_af_set(struct x86_emu_mod *mod, int v)
{
    return 0;
}

static int x86_emu_af_get(struct x86_emu_mdo *mod)
{
    return 0;
}

static int x86_emu_zf_set(struct x86_emu_mod *mod, int v)
{
    return 0;
}

static int x86_emu_zf_get(struct x86_emu_mdo *mod)
{
    return 0;
}

static int x86_emu_sf_set(struct x86_emu_mod *mod, int v)
{
    return 0;
}

static int x86_emu_sf_get(struct x86_emu_mdo *mod)
{
    return 0;
}

static int x86_emu_tf_set(struct x86_emu_mod *mod, int v)
{
    return 0;
}

static int x86_emu_tf_get(struct x86_emu_mdo *mod)
{
    return 0;
}

static int x86_emu_ief_set(struct x86_emu_mod *mod, int v)
{
    return 0;
}

static int x86_emu_ief_get(struct x86_emu_mdo *mod)
{
    return 0;
}

static int x86_emu_df_get(struct x86_emu_mdo *mod)
{
    return 0;
}

static int x86_emu_df_set(struct x86_emu_mod *mod, int v)
{
    return 0;
}

static int x86_emu_of_get(struct x86_emu_mdo *mod)
{
    return 0;
}

static int x86_emu_of_set(struct x86_emu_mod *mod, int v)
{
    return 0;
}

static uint32_t x86_emu_reg_val_get(int oper_siz, struct x86_emu_reg *reg)
{
    switch (oper_siz/8)
    { 
    case 1:
        return reg->u.r8;

    case 2:
        return reg->u.r16;

    case 4:
        return reg->u.r32;
    }

    return 0;
}

static int x86_emu__push_reg(struct x86_emu_mod *mod, int oper_siz1, struct x86_emu_reg *reg)
{
    int oper_siz = oper_siz1 ? oper_siz1 : mod->inst.oper_size;
    int top = mod->stack.top;
    x86_emu_operand_t *oper = NULL;

    if (mod->stack.top >= mod->stack.size)
    {
        printf("x86_emu__push_reg() failed when stack overflow()");
        return -1;
    }

    oper = &mod->stack.data[mod->stack.top + 1];

    switch (oper_siz/8)
    {
    case 1:
        oper->kind = a_reg8;
        break;

    case 2:
        oper->kind = a_reg16;
        break;

    case 4:
        oper->kind = a_reg32;
        break;

    default:
        assert(0);
        break;
    }

    oper->u.reg = *reg;

    mod->stack.top++;
    return 0;
}

static int x86_emu__push_imm8(struct x86_emu_mod *mod, uint8_t imm8)
{
    x86_emu_operand_t *operand;

    if ((mod->stack.top + 1) >= mod->stack.size)
    {
        assert(0);
    }

    operand = &mod->stack.data[mod->stack.top + 1];
    operand->kind = a_imm8;
    operand->u.imm8 = imm8;

    mod->stack.top++;

    return 0;
}

static int x86_push_imm16(struct x86_emu_mod *mod, uint16_t imm16)
{
    x86_emu_operand_t *operand;

    if ((mod->stack.top + 1) >= mod->stack.size)
    {
        assert(0);
    }

    operand = &mod->stack.data[mod->stack.top + 1];
    operand->kind = a_imm16;
    operand->u.imm16 = imm16;

    mod->stack.top++;
    return 0;
}

static int x86_push_imm32(struct x86_emu_mod *mod, uint16_t imm32)
{
    x86_emu_operand_t *operand;

    if ((mod->stack.top + 1) >= mod->stack.size)
    {
        assert(0);
    }

    operand = &mod->stack.data[mod->stack.top + 1];
    operand->kind = a_imm32;
    operand->u.imm32 = imm32;

    mod->stack.top++;
    return 0;
}

static x86_emu_operand_t *x86_emu__pop(struct x86_emu_mod *mod)
{
    if (mod->stack.top < 0)
    {
        printf("x86_emu__pop() failed when stack downflow. %s:%d\r\n", __FILE__, __LINE__);
        return NULL;
    }

    mod->stack.top--;

    return &mod->stack.data[mod->stack.top+1];
}

#ifdef __cplusplus
}
#endif
