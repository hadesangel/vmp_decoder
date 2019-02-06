
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "x86_emu.h"
#include "mbytes.h"

#define time2s(_t)                  ""
#define print_err                   printf

#define X86_EMU_EXTERNAL_CALL       0xb1b1b1b1

#define XE_EFLAGS_BIT_GET(mod1, flag1)    (!!(mod1->eflags.eflags & flag1))
#define x86_emu_mem_fix(_va)    (uint8_t *)((uint64_t)(_va) | mod->addr64_prefix)

#define X86_EMU_BIT(_bit_base, _bit_offset)             ((_bit_base) & (1 << (_bit_offset)))
#define X86_EMU_BIT_CLEAR(_bit_base, _bit_offset)       ((_bit_base) &= ~(1 << (_bit_offset)))

static struct x86_emu_reg *x86_emu_reg_get(struct x86_emu_mod *mod, int reg_type);
static int x86_emu_modrm_analysis2(struct x86_emu_mod *mod, uint8_t *cur, int oper_size1, int *dst_type, int *src_type, x86_emu_operand_t *imm);
// 在执行加法的修改状态时，必须指明数据进行的是加法还是减法
// 为什么呢?在解释这个问题之前，先问大家2个问题
// 
// 问题1，在x86指令这个层面，所有的负数都会转成补码，那么为什么
// 在设置CF标志时，白皮书上会写，当产生进位和借位时设置CF。理论上转成补码后
// 所有的操作都是加法，那么应该只有加法（进位），没有减法（借位）才对，那么
// 书上这么说是什么意思呢？
//
// 问题2， 
//     mov eax, 5
//     mov ecx, 4
//     cmp eax, ecx
//   eax = 0x00000005
//   ecx = 0x00000004
// 在执行cmp时，实际上是执行减法，所以
//   ecx = 0xfffffffc
//   eax = 0x00000005
//    +
//      1 0x00000001
// 然后设置了CF位，但是我们明显看出eax是大的，所以不该设置CF
// 这个问题的原因是，当执行减法时，补码的转换被认为是借位，假如补码在加法后
// 产生了进位，那么借位和进位会互相抵消，只有抵消不了的，才是实际真实产生的
// 进位和借位
static int x86_emu_add_modify_status(struct x86_emu_mod *mod, uint32_t dst, uint32_t src, int borrow);

#define x86_emu_reg8_get(reg, reg_type)     ((reg_type < 4) ? (reg)->u._r16.r8l:(reg)->u._r16.r8h)

uint8_t *x86_emu_access_esp(struct x86_emu_mod *mod);
uint8_t *x86_emu_reg8_get_ptr(struct x86_emu_mod *mod, int reg_type);
uint8_t *x86_emu_reg8_get_known_ptr(struct x86_emu_mod *mod, int reg_type);

int x86_emu_stack_top(struct x86_emu_mod *mod);
static int x86_emu_af_set(struct x86_emu_mod *mod, int v);
static int x86_emu_af_get(struct x86_emu_mod *mod);
static int x86_emu_cf_set(struct x86_emu_mod *mod, uint32_t v);
static int x86_emu_cf_get(struct x86_emu_mod *mod);
static int x86_emu_of_set(struct x86_emu_mod *mod, int v);
static int x86_emu_of_get(struct x86_emu_mod *mod);
static int x86_emu_sf_set(struct x86_emu_mod *mod, int v);
static int x86_emu_sf_get(struct x86_emu_mod *mod);
static int x86_emu_zf_set(struct x86_emu_mod *mod, int v);
static int x86_emu_zf_get(struct x86_emu_mod *mod);
static int x86_emu_pf_set(struct x86_emu_mod *mod, int v);
static int x86_emu_pf_get(struct x86_emu_mod *mod);
static int x86_emu_df_set(struct x86_emu_mod *mod, int v);
static int x86_emu__push_reg(struct x86_emu_mod *mod, int oper_siz1, struct x86_emu_reg *reg);
static int x86_emu__push_imm8(struct x86_emu_mod *mod, uint8_t imm8);
static int x86_emu__push_imm16(struct x86_emu_mod *mod, uint16_t imm16);
static int x86_emu__push_imm32(struct x86_emu_mod *mod, uint32_t imm32);
static int x86_emu__push(struct x86_emu_mod *mod, uint8_t *known, uint8_t *data, int len);
int x86_emu_pushfd(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_push_reg(struct x86_emu_mod *mod, int reg_type);

int x86_emu_add(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_lea(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_mov(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_xor(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_bt(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_bts(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_btc(struct x86_emu_mod *mod, uint8_t *code, int len);
static int x86_emu_dec(struct x86_emu_mod *mod, uint8_t *code, int len);

int x86_emu_rol(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_ror(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_rcl(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_rcr(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_shr(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_neg(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_bsf(struct x86_emu_mod *mod, uint8_t *code, int len);

// todo:
int x86_emu_bswap(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_clc(struct x86_emu_mod *mod, uint8_t *code, int len);

static uint32_t x86_emu_reg_val_get(int oper_siz, struct x86_emu_reg *reg);
static uint32_t x86_emu_reg_val_get2(struct x86_emu_mod *mod, int reg_type);

/* 在CPU模拟器的内部，所有的内存访问，都需要做一层模拟器内存到真实地址的映射才行。
 * 做的转换有以下几种：
 * 1. 32位地址到64位地址的转换
 * 2. PE文件内部 相对文件地址 到 rva 的转换 */
static uint8_t *x86_emu_access_mem(struct x86_emu_mod *mod, uint32_t addr);

#define X86_EMU_REG_IS_KNOWN(_op_siz, _reg)                 (((_op_siz == 32) && ((_reg)->known == 0xffffffff)) || ((_op_siz == 16) && (((_reg)->known & 0xffff) == 0xffff)))
#define X86_EMU_REG8_IS_KNOWN(_reg_type, _reg)              ((_reg_type < 4) ? ((_reg)->known & 0xff):((_reg)->known & 0xff00))
#define X86_EMU_REG_H8_IS_KNOWN(_reg)                       ((_reg)->known & 0x0000ff00)
#define X86_EMU_REG_BIT_IS_KNOWN(_op_siz, _reg, _bit_pos)   ((_reg)->known & (1 << (_bit_pos % _op_siz)))
#define X86_EMU_EFLAGS_BIT_IS_KNOWN(_bit)                   ((_bit) >= 0)

#define SIB_GET_SCALE(_c)   ((_c) >> 6)
#define SIB_GET_BASE(_c)    ((_c) & 7)
#define SIB_GET_INDEX(_c)   (((_c) >> 3) & 7)

#define X86_EMU_REG_AL(_mod)            (_mod)->eax.u._r16.r8l
#define X86_EMU_REG_AH(_mod)            (_mod)->eax.u._r16.r8h
#define X86_EMU_REG_BL(_mod)            (_mod)->ebx.u._r16.r8l
#define X86_EMU_REG_BH(_mod)            (_mod)->ebx.u._r16.r8h
#define X86_EMU_REG_CL(_mod)            (_mod)->ecx.u._r16.r8l
#define X86_EMU_REG_CH(_mod)            (_mod)->ecx.u._r16.r8h
#define X86_EMU_REG_DL(_mod)            (_mod)->edx.u._r16.r8l
#define X86_EMU_REG_DH(_mod)            (_mod)->edx.u._r16.r8h

#define x86_emu_dynam_le_read(_word_siz,_code) \
    (((_word_siz) == 32) ? mbytes_read_int_little_endian_4b(_code) \
        :((_word_siz == 16)?mbytes_read_int_little_endian_2b(_code):((_code)[0])))

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

#define x86_emu_dynam_mem_set(_mem, _dst) \
    do { \
        if (mod->inst.oper_size == 16) \
        {  \
            mbytes_write_int_little_endian_2b(_mem, (_dst)->u.r16); \
        } \
        else if (mod->inst.oper_size == 32) \
        { \
            mbytes_write_int_little_endian_4b(_mem, (_dst)->u.r32); \
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

#define x86_emu_dynam_oper_imm(_dst_reg1, _oper, _imm) \
    do \
    { \
        if (mod->inst.oper_size == 16) \
        { \
            (_dst_reg1)->u.r16 _oper _imm; \
        } \
        else if (mod->inst.oper_size == 32) \
        { \
            (_dst_reg1)->u.r32 _oper _imm; \
        } \
    } while (0)

#define x86_emu_add_dynam_modify_status_rr(_dst_reg, _src_reg, _sign, _cf) \
    do \
    {  \
        if (mod->inst.oper_size == 32) \
        { \
            x86_emu_add_modify_status(mod, _dst_reg->u.r32, _sign ? (~((_src_reg)->u.r32 + _cf) + 1):(_src_reg)->u.r32, _sign); \
        } \
        else if (mod->inst.oper_size == 16) \
        { \
            x86_emu_add_modify_status(mod, dst_reg->u.r16, _sign ? (~((_src_reg)->u.r16 + _cf) + 1):(_src_reg)->u.r16, _sign); \
        } \
    } while (0)

#define x86_emu_add_dynam_rr(_dst_reg, oper, _src_reg, _cf) \
    do{ \
        if (mod->inst.oper_size == 32) \
        { \
            _dst_reg->u.r32 oper ((_src_reg)->u.r32 + _cf); \
        } \
        else if (mod->inst.oper_size == 16) \
        { \
            _dst_reg->u.r16 oper ((_src_reg)->u.r16 + _cf); \
        } \
    } while (0)

#define x86_emu_reg8_oper(_dst_reg, _reg_type, _oper)  \
    do{ \
        if (reg_type < 4) \
        { \
            _dst_reg->u._r16.r8l _oper; \
        } \
        else \
        { \
            _dst_reg->u._r16.r8h _oper; \
        } \
    } while (0)

#define X86_EMU_OPER_SET            1
#define X86_EMU_OPER_MOVE           X86_EMU_OPER_MOVE
#define X86_EMU_OPER_ADD            2
#define X86_EMU_OPER_NOT            3
#define X86_EMU_OPER_XOR            4

#define counts_of_array(_a)         (sizeof (_a) / sizeof (_a[0]))

struct x86_emu_mod *x86_emu_create(struct x86_emu_create_param *param)
{
    struct x86_emu_mod *mod;
    struct x86_emu_reg *regs;
    int i;

    mod = (struct x86_emu_mod *)calloc(1, sizeof (mod[0]));
    if (!mod)
    {
        printf("x86_emu_create() failed when calloc(). %s:%d", __FILE__, __LINE__);
        return NULL;
    }

    mod->pe_mod = param->pe_mod;

    mod->eax.type = OPERAND_TYPE_REG_EAX;
    mod->ebx.type = OPERAND_TYPE_REG_EBX;
    mod->ecx.type = OPERAND_TYPE_REG_ECX;
    mod->edx.type = OPERAND_TYPE_REG_EDX;
    mod->edi.type = OPERAND_TYPE_REG_EDI;
    mod->esi.type = OPERAND_TYPE_REG_ESI;
    mod->ebp.type = OPERAND_TYPE_REG_EBP;
    mod->esp.type = OPERAND_TYPE_REG_ESP;

    for (i = 0, regs = &mod->eax; i < 8; i++)
    {
        regs[i].known = UINT_MAX;
    }

    mod->ebx.u.r32 = 0xb81000;
    mod->word_size = 32;

    // 因为系统的堆栈是从尾部增长的，所以我们这里也从尾部开始增长
    // 这样会导致一个后果那就是堆栈无法扩充，以后在该吧。TODO:stack
    // 模拟器的堆栈分为2部分，一部分用来存数据，一部分用来存放 known
    // 信息，因为我们是静态分析，用来去除死代码和常量计算的，必须得
    // 在程序的某个点上确认当前这个变量是否可计算，需要清楚这个变量
    // 是否是Known的。
    mod->stack.top = 128 * 1024;
    mod->stack.size = 128 * 1024;
    mod->stack.known = (uint8_t *)calloc(1, mod->stack.size);
    mod->stack.data = (uint8_t *)calloc(1, mod->stack.size);

    // esp寄存器比较特别，理论上所有的寄存器开始时都是unknown状态的
    // 但是因为我们实际在操作堆栈时，依赖于esp，所以假设一开始esp
    // 有值。另外看起来一些比较小的程序，虽然用64位编译，但是他们的
    // 高32位都是一样的，所以我们这里直接把高32位揭掉，只有在需要访问
    // 内存的时候，才把这个值加上去，具体可以看x86_emu_access_mem
    mod->esp.u.r32 = (uint32_t)((uint64_t)mod->stack.data & UINT_MAX) + mod->stack.top;
    mod->esp.known = UINT_MAX;

    mod->stack.esp_start = (uint32_t)((uint64_t)mod->stack.data & UINT_MAX);
    mod->stack.esp_end = mod->esp.u.r32 - 1;

    mod->addr64_prefix = (uint64_t)mod->stack.data & 0xffffffff00000000;

    *((int *)mod->mem.external_call) = X86_EMU_EXTERNAL_CALL;

    mod->hlp = param->hlp;

    mod->eflags.known = UINT_MAX;
    // 看起来系统默认EFLAGS里的B1和IEF是开启的
    mod->eflags.eflags |= XE_EFLAGS_B1;
    mod->eflags.eflags |= XE_EFLAGS_IEF;

    if (!mod->stack.data || !mod->stack.known)
    {
        print_err ("[%s] err:  failed with calloc(). %s:%d\r\n", time2s (0), __FILE__, __LINE__);
        return NULL;
    }

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

// counts 1-bits in world
static int count_1bit (uint32_t x)
{
    x = x - ((x >> 1) & 0x55555555);
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
    x = (x + (x >> 4)) & 0x0F0F0F0F;
    x = x + (x >> 8);
    x = x + (x >> 16);
    return x & 0x0000003F;
}

int x86_emu_push(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    uint32_t imm32;
    uint16_t imm16;

    switch (code[0])
    {
    case 0x50:
    case 0x51:
    case 0x52:
    case 0x53:
    case 0x54:
    case 0x55:
    case 0x56:
    case 0x57:
        x86_emu_push_reg(mod, code[0] - 0x50);
        break;

    case 0x68:
        if (mod->inst.oper_size == 32)
        {
            imm32 = mbytes_read_int_little_endian_4b(code + 1);
            x86_emu__push_imm32(mod, imm32);
        }
        else
        {
            imm16 = mbytes_read_int_little_endian_4b(code + 1);
            x86_emu__push_imm16(mod, imm16);
        }

        break;

    default:
        return -1;
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

    return x86_emu__push(mod, (uint8_t *)&reg->known, (uint8_t *)&reg->u.r32, mod->inst.oper_size / 8);
}

int x86_emu_push_imm(struct x86_emu_mod *mod, int val)
{
    return 0;
}

static int x86_emu__pop(struct x86_emu_mod *mod, int len)
{
    int top = (int)(x86_emu_access_esp(mod) - mod->stack.data);

    if ((top + len) >= mod->stack.size)
    {
        printf("[start:%x] [end:%x] [top=%x] [len=%x]\n", 
            mod->stack.esp_start, mod->stack.esp_end, top, len);
        assert(0);
    }

    mod->esp.u.r32 += len;

    return 0;
}

static int x86_emu__push(struct x86_emu_mod *mod, uint8_t *known, uint8_t *data, int len)
{
    int top = (int)(x86_emu_access_esp(mod) - mod->stack.data);

    if (top > mod->stack.size)
    {
        print_err ("[%s] err:  x86_emu__push() failed with overflow. %s:%d\r\n", time2s (0), __FILE__, __LINE__);
        return -1;
    }

    memcpy (mod->stack.data + (top - len), data, len);
    memcpy (mod->stack.known + (top - len), known, len);

    mod->esp.u.r32 -= len;

    return 0;
}

int x86_emu_pushfd (struct x86_emu_mod *mod, uint8_t *code, int len)
{
    return x86_emu__push(mod, (uint8_t *)&mod->eflags.known, (uint8_t *)&mod->eflags.eflags, sizeof (mod->eflags.eflags));
}

int x86_emu_popfd(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    mod->eflags.eflags = mbytes_read_int_little_endian_4b(mod->stack.data + x86_emu_stack_top(mod));
    mod->eflags.known = mbytes_read_int_little_endian_4b(mod->stack.known + x86_emu_stack_top(mod));
    x86_emu__pop(mod, 4);
    return 0;
}

// 右移指令的操作数不止是寄存器，但是这个版本中，先只处理寄存器
int x86_emu_shrd (struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int cts;
    struct x86_emu_reg *dst_reg, *src_reg;

    switch (code[0])
    {
    case 0xac:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
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

    default:
        return -1;
    }
    return 0;
}

#define X86_EMU_ROL(oper_size1, orig_cts1, dst1) \
    do \
    {  \
        int tmp_counts, tmp_cf; \
        if (oper_size1 == 8)        tmp_counts = (orig_cts1 & 0x1f) % 9; \
        if (oper_size1 == 16)       tmp_counts = (orig_cts1 & 0x1f) % 17; \
        if (oper_size1 == 32)       tmp_counts = (orig_cts1 & 0x1f); \
        if (oper_size1 == 64)       tmp_counts = (orig_cts1 & 0x3f); \
 \
        for (; tmp_counts; tmp_counts--) \
        { \
            tmp_cf = (dst1) & (1 << (oper_size1 - 1)); \
            dst1 = (dst1 << 1) + !!tmp_cf; \
        } \
 \
        if ((orig_cts1) & 0x1f) \
            x86_emu_cf_set(mod, (dst1) & 1); \
 \
        if (((orig_cts1) & 0x1f) == 1) \
            x86_emu_of_set(mod, ((orig_cts1) >> (oper_size1 - 1)) ^ x86_emu_cf_get(mod)); \
    } while (0)

int x86_emu_rol(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *dst_reg;
    uint8_t *dst8;
    int count = -1;
    switch (code[0])
    {
    case 0xc0:
        // 不要问我为什么这样算counts，白皮书上这样写的
        dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
        mod->inst.oper_size = 8;
        X86_EMU_ROL(mod->inst.oper_size, code[2], dst8[0]);

        break;

    case 0xc1:
        if (count == -1) count = code[2];
    case 0xd1:
        if (count == -1) count = 1;
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (mod->inst.oper_size == 32)
        {
            X86_EMU_ROL(mod->inst.oper_size, count, dst_reg->u.r32);
        }
        else
        {
            X86_EMU_ROL(mod->inst.oper_size, count, dst_reg->u.r16);
        }
        break;

    case 0xd0:
        if (count == -1) count = 1;
    case 0xd2:
        if (count == -1) count = X86_EMU_REG_CL(mod);
        dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
        mod->inst.oper_size = 8;
        X86_EMU_ROL(mod->inst.oper_size, count, dst8[0]);
        break;

    default:
        return -1;
    }

    return 0;
}

int x86_emu_ror(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *reg;
    int reg_type, cts = -1;
    uint8_t *dst8;

    switch (code[0])
    {
    case 0xc0:
        if (cts == -1) 
        { 
            mod->inst.oper_size = 8;
            cts = code[2];
        }
    case 0xc1:
        if (cts == -1) cts = code[2];
    case 0xd0:
        if (cts == -1)
        {
            mod->inst.oper_size = 8;
            cts = 1;
        }
    case 0xd1:
        if (cts == -1) cts = 1;
    case 0xd2:
        if (cts == -1)
        {
            mod->inst.oper_size = 8;
            cts = X86_EMU_REG_CL(mod);
        }
    case 0xd3:
        if (cts == -1) cts = X86_EMU_REG_CL(mod);
        reg = x86_emu_reg_get(mod, reg_type = MODRM_GET_RM(code[1]));
        if (mod->inst.oper_size == 32)
        {
            reg->u.r32 = (reg->u.r32 >> cts) | (reg->u.r32 << (32 - cts));
        }
        else if (mod->inst.oper_size == 16)
        {
            reg->u.r16 = (reg->u.r16 >> cts) | (reg->u.r16 << (16 - cts));
        }
        else if (mod->inst.oper_size == 8)
        {
            dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
            dst8[0] = (dst8[0] >> cts) | (dst8[0] << (8 - cts));
        }
        break;

    default:
        return -1;
    }
    return 0;
}


#define X86_EMU_RCL(oper_size1, count1, dst1) \
    do { \
        int tmp_count, tmp_cf; \
        if (oper_size1 == 8)        tmp_count = (count1 & 0x1f) % 9; \
        if (oper_size1 == 16)       tmp_count = (count1 & 0x1f) % 17; \
        if (oper_size1 == 32)       tmp_count = (count1 & 0x1f); \
        if (oper_size1 == 64)       tmp_count = (count1 & 0x3f); \
 \
        for (; tmp_count; tmp_count--) \
        { \
            tmp_cf = (dst1 >> ((oper_size1) - 1)) & 1; \
            dst1 = (dst1 << 1) + x86_emu_cf_get(mod); \
            x86_emu_cf_set(mod, tmp_cf); \
        } \
    } while (0)

int x86_emu_rcl(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *dst_reg;
    uint8_t *dst8;
    int count = -1;

    switch (code[0])
    {
    case 0xc0:
        if (count == -1)    count = code[2];
    case 0xd2:
        if (count == -1)    count = X86_EMU_REG_CL(mod);
        dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));

        X86_EMU_RCL(8, count, dst8[0]);

        // 在白皮书上还有一段是计算overflow flag的，我没加
        // todo:
        break;

    case 0xc1:
        if (count == -1) count = code[2];
    case 0xd3:
        if (count == -1) count = X86_EMU_REG_CL(mod);
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (mod->inst.oper_size == 32)
        {
            X86_EMU_RCL(32, count, dst_reg->u.r32);
        }
        else if (mod->inst.oper_size == 16)
        {
            X86_EMU_RCL(16, count, dst_reg->u.r16);
        }
        break;

    default:
        return -1;
    }
    return 0;
}

#define X86_EMU_RCR(oper_size1, orig_cts1, dst1) \
    do \
    {  \
        int tmp_counts, tmp_cf; \
        if (oper_size1 == 8)        tmp_counts = ((orig_cts1) & 0x1f) % 9; \
        if (oper_size1 == 16)       tmp_counts = ((orig_cts1) & 0x1f) % 17; \
        if (oper_size1 == 32)       tmp_counts = ((orig_cts1) & 0x1f); \
        if (oper_size1 == 64)       tmp_counts = ((orig_cts1) & 0x3f); \
 \
        if (((orig_cts1) & (oper_size1 - 1)) == 1) \
        { \
            x86_emu_of_set(mod, (dst1 >> (oper_size1 - 1))^x86_emu_cf_get(mod)); \
        } \
 \
        for (; tmp_counts; tmp_counts--) \
        { \
            tmp_cf =  (dst1)&1; \
            dst1 = (dst1 << 1) | (tmp_cf << (oper_size1 - 1)); \
            x86_emu_cf_set(mod, tmp_cf); \
        } \
    } while (0)

int x86_emu_rcr(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int count = -1;
    struct x86_emu_reg *dst_reg;

    switch (code[0])
    {
    case 0xc1:
        if (count == -1) count = code[2];
    case 0xd3:
        if (count == -1) count = X86_EMU_REG_CL(mod);
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (mod->inst.oper_size == 32)
        { 
            X86_EMU_RCR(mod->inst.oper_size, count, dst_reg->u.r32);
        }
        else
        {
            X86_EMU_RCR(mod->inst.oper_size, count, dst_reg->u.r16);
        }
        break;

    default:
        return -1;
    }
    return 0;
}

int x86_emu_shr(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *dst_reg;
    int tmp_count;

#define SHR_COUNT_MASK      0x1f

    switch (code[0])
    {
    case 0xc1:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        tmp_count = code[2] & SHR_COUNT_MASK;

X86_EMU_SHR_LABEL:
        if (mod->inst.oper_size == 32)
        { 
            x86_emu_cf_set(mod, dst_reg->u.r32 & (1 << (tmp_count - 1)));
            dst_reg->u.r32 >>= tmp_count;
        }
        else
        {
            x86_emu_cf_set(mod, dst_reg->u.r16 & (1 << (tmp_count - 1)));
            dst_reg->u.r16 >>= tmp_count;
        }

        if (tmp_count == 1)
        { 
            x86_emu_of_set(mod, (dst_reg->u.r32 >> (mod->inst.oper_size - 1)) & 1);
        }
        break;

    case 0xd3:
        tmp_count = X86_EMU_REG_CL(mod) & 0x1f;
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        goto X86_EMU_SHR_LABEL;

    default:
        return -1;
    }

    return 0;
}

int x86_emu_neg(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *dst_reg;
    uint8_t *dst8;

    switch (code[0])
    {
    case 0xf6:
        dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
        x86_emu_cf_set(mod, dst8[0]);
        dst8[0] = -(char)dst8[0];
        break;

    case 0xf7:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, dst_reg))
        {
            if (((mod->inst.oper_size == 32) && dst_reg->u.r32 == 0)
                || ((mod->inst.oper_size == 16) && dst_reg->u.r16 == 0))
            {
                x86_emu_cf_set(mod, 0);
            }
            else
            {
                x86_emu_cf_set(mod, 1);
            }

            // todo, uint32_t加负号，能否正确的转补码
            if (mod->inst.oper_size == 32)
            {
                dst_reg->u.r32 = -(int32_t)dst_reg->u.r32;
            }
            else if (mod->inst.oper_size == 16)
            {
                dst_reg->u.r16 = -(int16_t)dst_reg->u.r16;
            }
        }
        break;

    default:
        return -1;
    }
    return 0;
}

int x86_emu_shl(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int cts = -1;
    x86_emu_reg_t *dst_reg;
    uint8_t *dst8;

    switch (code[0])
    {
    case 0xc0:
        cts = code[2] & 0x1f;
    case 0xd2:
        if (cts == -1) cts = X86_EMU_REG_CL(mod);
        mod->inst.oper_size = 8;
        dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
        x86_emu_cf_set(mod, (dst8[0] & (1 << (8 - cts))));
        dst8[0] <<= cts;
        break;

    case 0xd3:
        if (cts == -1) cts = X86_EMU_REG_CL(mod);
    case 0xc1:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (cts == -1) cts = code[2] & 0x1f;

        if (mod->inst.oper_size == 32)
        {
            x86_emu_cf_set(mod, (dst_reg->u.r32 & (1 << (32 - cts))));
            dst_reg->u.r32 <<= cts;
        }
        else if (mod->inst.oper_size == 16)
        {
            x86_emu_cf_set(mod, (dst_reg->u.r16 & (1 << (16 - cts))));
            dst_reg->u.r16 <<= cts;
        }
        break;

    default:
        return -1;
    }
    return 0;
}

int x86_emu_sar(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    x86_emu_reg_t *dst_reg;
    int cts;

    switch (code[0])
    {
    case 0xd3:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (mod->inst.oper_size == 32)
        {
            dst_reg->u.r32 >>= (cts = X86_EMU_REG_CL(mod) & (mod->inst.oper_size - 1));
        }
        else if (mod->inst.oper_size == 16)
        {
            dst_reg->u.r16 >>= (cts = X86_EMU_REG_CL(mod) & (mod->inst.oper_size - 1));
        }

        if (cts && X86_EMU_REG_CL(mod))
        {
            x86_emu_of_set(mod, 0);
        }
        break;

    default:
        return -1;
    }

    return 0;
}

#define BIT_TEST    0
#define BIT_SET     1
#define BIT_CLEAR   2
int x86_emu_bt_oper(struct x86_emu_mod *mod, uint8_t *code, int len, int oper)
{
    struct x86_emu_reg *dst_reg;
    uint32_t src_val, dst_val;
    x86_emu_operand_t src_imm;

    memset(&src_imm, 0 , sizeof (src_imm));

    x86_emu_modrm_analysis2(mod, code, 0, NULL, NULL, &src_imm);

    dst_reg = x86_emu_reg_get (mod, MODRM_GET_RM(code[0]));
    /* 源操作数已知的情况下，只要目的操作的src位bit是静态可取的，那么就可以计算的 */
    if (X86_EMU_REG_IS_KNOWN (mod->inst.oper_size, &src_imm.u.reg)
        && (1 | (src_val = x86_emu_reg_val_get(mod->inst.oper_size, &src_imm.u.reg)))
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
    int pos;
    struct x86_emu_reg *dst_reg, *src_reg;

    dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
    switch (code[0])
    {
    case 0xa3:
        src_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        pos = src_reg->u.r32 & ((1 << mod->inst.oper_size) - 1) & (mod->inst.oper_size - 1);
        x86_emu_cf_set(mod, X86_EMU_BIT(dst_reg->u.r32, pos));
        break;

    case 0xba:
        pos = code[2] & 7;
        x86_emu_cf_set(mod, X86_EMU_BIT(dst_reg->u.r32, pos));
        break;

    default:
        return -1;
    }

    return 0;
}

int x86_emu_setz(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    uint8_t *dst8;

    dst8 = x86_emu_reg8_get_ptr(mod, code[1]);
    if (x86_emu_zf_get(mod))
    {
        dst8[0] = 1;
    }

    return 0;
}

int x86_emu_setnz(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    uint8_t *dst8;

    dst8 = x86_emu_reg8_get_ptr(mod, code[1]);
    if (!x86_emu_zf_get(mod))
    {
        dst8[0] = 1;
    }

    return 0;
}

int x86_emu_setp(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    uint8_t *dst8;
    if(x86_emu_pf_get(mod) == 1)
    { 
        dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
        dst8[0] = 1;
    }
    return 0;
}

int x86_emu_bts(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    switch (code[0])
    {
    case 0xab:
        x86_emu_bt_oper(mod, code + 1, len --, BIT_SET);
        break;

    default:
        return -1;
    }
    return 0;
}

int x86_emu_btc(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *dst_reg;
    switch (code[0])
    {
    case 0xba:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        x86_emu_cf_set(mod, X86_EMU_BIT(dst_reg->u.r32, code[1] & (mod->inst.oper_size - 1)));
        dst_reg->u.r32 ^= X86_EMU_BIT(dst_reg->u.r32, code[1] & (mod->inst.oper_size - 1));
        break;

    case 0xbb:
        x86_emu_bt_oper(mod, code + 1, len - 1, BIT_CLEAR);
        break;

    default:
        return -1;
    }

    return 0;
}

int x86_emu_xor(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *src_reg, *dst_reg, src_imm = {0};
    int reg_type;
    uint8_t *dst8;

    switch (code[0])
    {
    case 0x32:
        mod->inst.oper_size = 8;
        dst_reg = x86_emu_reg_get(mod, (reg_type = MODRM_GET_REG(code[1])));
        x86_emu_reg8_oper(dst_reg, reg_type, ^= (uint8_t)x86_emu_reg_val_get2(mod, MODRM_GET_RM(code[1])));
        break;

    case 0x33:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));

        if (MODRM_GET_REG(code[1]) == MODRM_GET_RM(code[1]))
            x86_emu_dynam_set(dst_reg, 0);
        else
            x86_emu_dynam_oper(dst_reg, ^= , src_reg);
        break;

    case 0x34:
        dst8 = x86_emu_reg8_get_ptr(mod, 0);
        dst8[0] ^= code[1];
        break;

    case 0x35:
        dst_reg = &mod->eax;
        if (mod->inst.oper_size == 32)
        {
            dst_reg->u.r32 ^= mbytes_read_int_little_endian_4b(code + 1);
        }
        else if (mod->inst.oper_size == 16)
        {
            dst_reg->u.r16 ^= mbytes_read_int_little_endian_2b(code + 1);
        }
        break;

    case 0x80:
        dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
        dst8[0] ^= code[2];
        break;

    case 0x81:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        src_imm.known = 0xffffffff;
        src_imm.u.r32 = (mod->inst.oper_size == 32) ? mbytes_read_int_little_endian_4b(code + 2)
            :mbytes_read_int_little_endian_2b (code + 2);

        x86_emu_dynam_oper(dst_reg, ^=, &src_imm);
        break;

    default:
        return -1;
    }

    x86_emu_of_set(mod, 0);
    x86_emu_cf_set(mod, 0);

    return 0;
}

int x86_emu_lea(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int dst_type = 0, src_type = 0;
    x86_emu_reg_t *dst_reg;
    x86_emu_operand_t src_imm;
    memset(&src_imm, 0, sizeof (src_imm));

    switch (code[0])
    {
    case 0x8d:
        x86_emu_modrm_analysis2(mod, code + 1, 0, NULL, NULL, &src_imm);
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        X86_EMU_REG_SET_r32(dst_reg, src_imm.u.mem.addr32);
        break;

    default:
        return -1;
    }
    return 0;
}

int x86_emu_mov(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int reg_type;
    struct x86_emu_reg *dst_reg = NULL, *src_reg;
    x86_emu_operand_t src_imm;
    uint8_t *new_addr, *dst8, *src8;

    switch (code[0])
    {
    case 0xb0:
    case 0xb1:
    case 0xb2:
    case 0xb3:
    case 0xb4:
    case 0xb5:
    case 0xb6:
    case 0xb7:
        dst8 = x86_emu_reg8_get_ptr(mod, code[0] - 0xb0);
        dst8[0] = code[1];
        dst8 = x86_emu_reg8_get_known_ptr(mod, code[0] - 0xb0);
        dst8[0] = 0xff;
        break;

    case 0xb8:
    case 0xb9:
    case 0xba:
    case 0xbb:
    case 0xbc:
    case 0xbd:
    case 0xbe:
    case 0xbf:
        dst_reg = x86_emu_reg_get(mod, code[0] - 0xb8);
        x86_emu_dynam_imm_set(dst_reg, code + 1);
        break;

    case 0xc6:
        dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
        dst8[0] = code[2];
        dst8 = x86_emu_reg8_get_known_ptr(mod, MODRM_GET_RM(code[1]));
        dst8[0] = 0xff;
        break;

    case 0x88:
        x86_emu_modrm_analysis2(mod, code + 1, 0, NULL, NULL, &src_imm);
        src_reg = x86_emu_reg_get(mod, reg_type = MODRM_GET_REG(code[1]));
        if (src_imm.kind == a_mem)
        {
            if ((src_imm.u.mem.known & UINT_MAX)
                && (new_addr = x86_emu_access_mem(mod, src_imm.u.mem.addr32)))
            {
                new_addr[0] = x86_emu_reg8_get(src_reg, reg_type);
            }
        }
        else
        {
            assert(0);
        }
        break;

    case 0x89:
        x86_emu_modrm_analysis2(mod, code + 1, 0, NULL, NULL, &src_imm);
        src_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        if (src_imm.kind == a_mem)
        {
            if ((src_imm.u.mem.known & UINT_MAX)
                && (new_addr = x86_emu_access_mem(mod, src_imm.u.mem.addr32)))
            {
                x86_emu_dynam_mem_set(new_addr, src_reg);
            }
        }
        else
        {
            dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
            if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, src_reg))
            {
                x86_emu_dynam_set(dst_reg, src_reg->u.r32);
            }
        }
        break;

    case 0x8a:
        dst_reg = x86_emu_reg_get(mod, reg_type = MODRM_GET_REG(code[1]));
        x86_emu_modrm_analysis2(mod, code + 1, 0, NULL, NULL, &src_imm);
        if (src_imm.kind == a_mem)
        {
            if ((src_imm.u.mem.known & UINT_MAX)
                && (new_addr = x86_emu_access_mem(mod, src_imm.u.mem.addr32)))
            {
                x86_emu_reg8_oper(dst_reg, reg_type, = new_addr[0]);
                dst_reg->known |= (reg_type < 4) ? 0x00ff:0xff00;
            }
        }
        else
        {
            dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_REG(code[1]));
            src8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
            dst8[0] = src8[0];
        }
        break;

    case 0x8b:
        memset(&src_imm, 0, sizeof (src_imm));
        x86_emu_modrm_analysis2(mod, code + 1, 0, NULL, NULL, &src_imm);
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));

        if (src_imm.kind == a_mem)
        {
            if (src_imm.u.mem.known & UINT_MAX)
            {
                uint8_t *new_addr = x86_emu_access_mem(mod, src_imm.u.mem.addr32);
                x86_emu_dynam_imm_set(dst_reg, new_addr);
            }
        }
        else
        {
            src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
            if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, src_reg))
            {
                x86_emu_dynam_set(dst_reg, src_reg->u.r32);
            }
        }
        break;

    default:
        return -1;
    }

    return 0;
}

int x86_emu_nop(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    return 0;
}

static int x86_emu_movsx(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *dst_reg, *src_reg;
    uint8_t *src8;

    switch (code[0])
    {
    case 0xbe:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        src8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
        if (mod->inst.oper_size == 32)
        {
            dst_reg->u.r32 = (int8_t)src8[0];
        }
        else if (mod->inst.oper_size == 16)
        {
            dst_reg->u.r16 = (int8_t)src8[0];
        }
        break;

    case 0xbf:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        dst_reg->u.r32 = (uint32_t)(int32_t)src_reg->u.r16;
        break;

    default:
        return -1;
    }

    return 0;

}

int x86_emu_add(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int  rm;
    x86_emu_reg_t *dst_reg, *src_reg;
    uint8_t *dst8, *src8;
    uint32_t i32, i16;

    switch (code[0])
    {
    case 0x02:
        dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_REG(code[1]));
        src8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
        x86_emu_add_modify_status(mod, dst8[0], src8[0], 0);
        dst8[0] = src8[0];
        break;

    case 0x03:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));

        x86_emu_add_dynam_modify_status_rr(dst_reg, src_reg, 0, 0);
        x86_emu_dynam_oper(dst_reg, +=, src_reg);
        break;

    case 0x04:
        dst8 = x86_emu_reg8_get_ptr(mod, 0);
        x86_emu_add_modify_status(mod, dst8[0], code[1], 0);
        dst8[0] += code[1];
        break;

    case 0x05:
        dst_reg = x86_emu_reg_get(mod, 0);
        if (mod->inst.oper_size == 32)
        {
            i32 = mbytes_read_int_little_endian_4b(code + 1);
            x86_emu_add_modify_status(mod, dst_reg->u.r32, i32, 0);
            dst_reg->u.r32 += i32;
        }
        else
        {
            i16 = mbytes_read_int_little_endian_2b(code + 1);
            x86_emu_add_modify_status(mod, dst_reg->u.r16, i16, 0);
            dst_reg->u.r16 += i16;
        }
        break;

    case 0x80:
        mod->inst.oper_size = 8;
        dst_reg = x86_emu_reg_get(mod, rm = MODRM_GET_RM(code[1]));
        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, dst_reg))
        {
            x86_emu_add_modify_status(mod, ((rm < 4) ?dst_reg->u._r16.r8l:dst_reg->u._r16.r8h), code[2], 0);
        }

        if (rm < 4)
        {
            dst_reg->u._r16.r8l += code[2];
        }
        else
        {
            dst_reg->u._r16.r8h += code[2];
        }
        break;

    case 0x81:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        x86_emu_add_modify_status(mod,
            (mod->inst.oper_size == 32) ? dst_reg->u.r32 : dst_reg->u.r16,
            ((mod->inst.oper_size == 32) ? mbytes_read_int_little_endian_4b(code + 2)
            :mbytes_read_int_little_endian_2b(code + 2)), 0);

        if (mod->inst.oper_size == 32)
        {
            dst_reg->u.r32 += mbytes_read_int_little_endian_4b(code + 2);
        }
        else
        {
            dst_reg->u.r16 += mbytes_read_int_little_endian_2b(code + 2);
        }
        break;

    default:
        return -1;
    }
    return 0;
}

static int x86_emu_xadd(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    x86_emu_reg_t *dst_reg, *src_reg;
    uint32_t tmp;

    switch (code[0])
    {
    case 0xc1:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        if (mod->inst.oper_size == 32)
        {
            x86_emu_add_modify_status(mod, dst_reg->u.r32, src_reg->u.r32, 0);
            tmp = dst_reg->u.r32 + src_reg->u.r32;
            src_reg->u.r32 = dst_reg->u.r32;
            dst_reg->u.r32 = tmp;
        }
        else
        {
            x86_emu_add_modify_status(mod, dst_reg->u.r16, src_reg->u.r16, 0);
            tmp = dst_reg->u.r16 + src_reg->u.r16;
            src_reg->u.r16 = dst_reg->u.r16;
            dst_reg->u.r16 = tmp;
        }
        break;

    default:
        return -1;
    }
    return 0;
}

int x86_emu_and(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg src_imm = {0}, *dst_reg = NULL, *src_reg = NULL;
    uint8_t *dst8, *src8;

    switch (code[0])
    {
    case 0x21:
        if (!dst_reg)
        {
            dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
            src_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        }
    case 0x23:
        if (!dst_reg)
        {
            dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
            src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        }
        if (mod->inst.oper_size == 32)
        {
            dst_reg->u.r32 &= src_reg->u.r32;
        }
        else
        {
            dst_reg->u.r16 &= src_reg->u.r16;
        }
        x86_emu_sf_set(mod, dst_reg->u.r32 & (1 < (mod->inst.oper_size - 1)));
        x86_emu_pf_set(mod, count_1bit((mod->inst.oper_size == 32) ? dst_reg->u.r32:dst_reg->u.r16));
        break;

    case 0x22:
        dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_REG(code[1]));
        src8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
        dst8[0] &= src8[0];
        break;

    case 0x25:
        if (mod->inst.oper_size == 32)
        {
            mod->eax.u.r32 &= mbytes_read_int_little_endian_4b(code + 1);
        }
        else if (mod->inst.oper_size == 16)
        {
            mod->eax.u.r16 &= mbytes_read_int_little_endian_2b(code + 1);
        }
        break;

    case 0x80:
        dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
        dst8[0] &= code[2];
        break;

    case 0x81:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (mod->inst.oper_size == 32)
        {
            dst_reg->u.r32 &= (uint32_t)mbytes_read_int_little_endian_4b(code + 2);
        }
        else
        {
            dst_reg->u.r16 &= (uint16_t)mbytes_read_int_little_endian_2b(code + 2);
        }

        x86_emu_sf_set(mod, dst_reg->u.r32 & (1 < (mod->inst.oper_size - 1)));
        x86_emu_pf_set(mod, count_1bit((mod->inst.oper_size == 32) ? dst_reg->u.r32:dst_reg->u.r16));
        break;

    default:
        return -1;
    }

    x86_emu_cf_set(mod, 0);
    x86_emu_of_set(mod, 0);

    return 0;
}

int x86_emu_or(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    x86_emu_reg_t *dst_reg = NULL, *src_reg = NULL;
    uint8_t *dst8, *src8;

    switch (code[0])
    {
    case 0x0a:
        dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_REG(code[1]));
        src8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
        dst8[0] |= src8[0];
        break;

    case 0x0b:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        x86_emu_dynam_oper(dst_reg, |=, src_reg);
        break;

    case 0x0d:
        if (mod->inst.oper_size == 32)
        {
            mod->eax.u.r32 |= mbytes_read_int_little_endian_4b(code + 1);
        }
        else if (mod->inst.oper_size == 16)
        {
            mod->eax.u.r16 |= mbytes_read_int_little_endian_2b(code + 1);
        }
        break;

    case 0x80:
        dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
        dst8[0] |= code[2];
        break;

    case 0x81:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (mod->inst.oper_size == 32)
        {
            dst_reg->u.r32 |= mbytes_read_int_little_endian_4b(code + 2);
        }
        else
        {
            dst_reg->u.r16 |= mbytes_read_int_little_endian_2b(code + 2);
        }
        break;

    default:
        return -1;
    }
    x86_emu_of_set(mod, 0);
    x86_emu_cf_set(mod, 0);
    return 0;
}

int x86_emu_cmovp(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *dst_reg, *src_reg;

    switch (code[0])
    {
    case 0x4a:
        if (x86_emu_pf_get(mod) == 1)
        {
            dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
            src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
            if (mod->inst.oper_size == 32)
            {
                dst_reg->u.r32 = src_reg->u.r32;
                dst_reg->known = src_reg->known;
            }
            else
            {
                dst_reg->u.r16 = src_reg->u.r16;
                dst_reg->known |= src_reg->known & 0xffff;
            }
        }
        break;

    default:
        return -1;
    }
    return 0;
}

int x86_emu_cmovl(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *dst_reg, *src_reg;
    if (x86_emu_sf_get(mod) != x86_emu_of_get(mod))
    {
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));

        if (mod->inst.oper_size == 32)
        { 
            dst_reg->u.r32 = src_reg->u.r32;
            dst_reg->known = src_reg->known;
        }
        else if (mod->inst.oper_size == 16)
        {
            dst_reg->u.r16 = src_reg->u.r16;
            dst_reg->known |= src_reg->known & 0xffff;
        }
    }
    return 0;
}

int x86_emu_cmovs(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *dst_reg, *src_reg;

    if (x86_emu_sf_get(mod) == 0)
    {
        return 0;
    }

    dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
    src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));

    x86_emu_dynam_oper(dst_reg, =, src_reg);

    return 0;
}

// 本来计算这个状态会带入cf的标志的，后来发现没有必要，而且在计算
// 减法时状态不对，直接让API在上层计算了带进来
static int x86_emu_add_modify_status(struct x86_emu_mod *mod, uint32_t dst, uint32_t src, int borrow)
{
    int oper_siz = mod->inst.oper_size;

    int sign_src = src & (1 << (oper_siz - 1)), sign_dst = dst & (1 << (oper_siz - 1)), sign_s;

    uint32_t s = 0;

    uint32_t cf = 0;
    int t1;

    switch (oper_siz / 8)
    {
    case 1:
        s = (uint8_t)((uint8_t)dst + (uint8_t)src);
    t1 = !!(((uint64_t)(uint8_t)dst + (uint64_t)(uint8_t)src) & ((uint64_t)1 << oper_siz));
        break;

    case 2:
        s = (uint16_t)((uint16_t)dst + (uint16_t)src);
    t1 = !!(((uint64_t)(uint16_t)dst + (uint64_t)(uint16_t)src) & ((uint64_t)1 << oper_siz));
        break;

    case 4:
    t1 = !!(((uint64_t)dst + (uint64_t)src) & ((uint64_t)1 << oper_siz));
        s = dst + src;
        break;
    }

    sign_s = s & (1 << (oper_siz - 1));

    if (src == 0)
        borrow = 0;


#if 1
    int cf2;
    if (sign_src != sign_dst)
    {
        x86_emu_cf_set(mod, cf2 = 0);
    }
    else
    {
        x86_emu_cf_set(mod, cf2 = (sign_s != sign_src));
    }
#endif

#if 1
    cf = !!(t1 - borrow);
    x86_emu_cf_set(mod, cf);
#endif


    if (cf != cf2)
        printf("[s:%x] = [dst:%x] + [src:%x], [%d:%d:%d], borrow:[%d]\n", 
            s, dst, src, t1, cf, cf2, borrow);

    if (((dst & 0xf) + (src & 0xf)) > 0xf)
    {
        x86_emu_af_set(mod, 1);
    }
    else
    {
        x86_emu_af_set(mod, 0);
    }

#if 0
    if (sign_src != sign_dst)
    {
        x86_emu_cf_set(mod, 0);
    }
    else
    {
        x86_emu_cf_set(mod, sign_s != sign_src);
    }
#endif

    if ((sign_src == sign_dst) && (sign_s != sign_src))
    {
        x86_emu_of_set(mod, 1);
    }

    x86_emu_zf_set(mod, src == dst);

    x86_emu_sf_set(mod, !!sign_s);

    x86_emu_pf_set(mod, !(count_1bit(s & 0xff) & 1));

    return 0;
}

int x86_emu_adc(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int ret;
    struct x86_emu_reg *dst_reg, *src_reg, src_imm = {0};
    uint8_t *dst8, *src8;

    switch(code[0])
    {
    case 0x12:
        dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_REG(code[1]));
        src8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
        assert(MODRM_GET_MOD(code[1]) == 0b11);
        x86_emu_add_modify_status(mod, dst8[0], src8[0] + x86_emu_cf_get(mod), 0);
        dst8[0] += src8[0] + x86_emu_cf_get(mod);
        break;
    case 0x13:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, dst_reg)
            && X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, src_reg)
            && X86_EMU_EFLAGS_BIT_IS_KNOWN((ret = x86_emu_cf_get(mod))))
        {
            x86_emu_add_dynam_modify_status_rr(dst_reg, src_reg, 0, ret);
            x86_emu_add_dynam_rr(dst_reg, +=, src_reg, ret);
        }
        break;

    case 0x80:
        dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
        x86_emu_add_modify_status(mod, dst8[0], code[2] + x86_emu_cf_get(mod), 0);
        dst8[0] += code[2] + x86_emu_cf_get(mod);
        break;

    case 0x81:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, dst_reg)
            && X86_EMU_EFLAGS_BIT_IS_KNOWN((ret = x86_emu_cf_get(mod))))
        {
            src_imm.u.r32 = (mod->inst.oper_size == 32) ? mbytes_read_int_little_endian_4b(code + 2):
                mbytes_read_int_little_endian_2b(code + 2);
            src_imm.known = 0xffffffff;
            x86_emu_add_dynam_modify_status_rr(dst_reg, &src_imm, 0, ret);
            x86_emu_add_dynam_rr(dst_reg, +=, &src_imm, ret);
        }
        break;

    default:
        return -1;
    }
    return 0;
}

int x86_emu_sbb(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int cf;
    struct x86_emu_reg  *dst_reg, *src_reg, src_imm = {0};

    switch (code[0])
    {
    case 0x1b:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));

        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, dst_reg)
            && X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, src_reg)
            && X86_EMU_EFLAGS_BIT_IS_KNOWN(cf = x86_emu_cf_get(mod)))
        {
            x86_emu_add_dynam_modify_status_rr(dst_reg, src_reg, 1,  cf);
            x86_emu_add_dynam_rr(dst_reg, -=, src_reg,  cf);
        }
        break;

    case 0x1d:
        if (mod->inst.oper_size == 32)
        {
            int32_t i32 = mbytes_read_int_little_endian_4b(code + 1);
            x86_emu_add_modify_status(mod, mod->eax.u.r32, - (i32 + 1), 1);
            mod->eax.u.r32 -= i32 + x86_emu_cf_get(mod);
        }
        else if (mod->inst.oper_size == 16)
        {
            int32_t i16 = mbytes_read_int_little_endian_2b(code + 1);
            x86_emu_add_modify_status(mod, mod->eax.u.r16, - (i16 + 1), 1);
            mod->eax.u.r16 -= mbytes_read_int_little_endian_2b(code + 1) + x86_emu_cf_get(mod);
        }
        break;

    default:
        return -1;
    }
    return 0;
}


int x86_emu_sub(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *dst_reg = NULL, *src_reg;
    uint8_t *dst8 = NULL, *ipos = NULL;
    uint32_t i32, i16;

    switch (code[0])
    {
    case 0x2b:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        x86_emu_add_dynam_rr(dst_reg, -=, src_reg, 0);
        break;

    case 0x2c:
        dst8 = x86_emu_reg8_get_ptr(mod, 0); // al
        x86_emu_add_modify_status(mod, dst8[0], - (int8_t)code[1], 1);
        dst8[0] -= code[1];
        break;

    case 0x80:
        dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
        x86_emu_add_modify_status(mod, dst8[0], - (int8_t)code[2], 1);
        dst8[0] -= code[2];
        break;

    case 0x2d:
        if (!dst_reg)
        {
            dst_reg = &mod->eax;
            ipos = code + 1;
        }
    case 0x81:
        if (!dst_reg)
        {
            dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
            ipos = code + 2;
        }
        if (mod->inst.oper_size == 32)
        {
            i32 = mbytes_read_int_little_endian_4b(ipos);
            x86_emu_add_modify_status(mod, dst_reg->u.r32, - (int)i32, 1);
            dst_reg->u.r32 -= i32;
        }
        else
        {
            i16 = mbytes_read_int_little_endian_2b(ipos);
            x86_emu_add_modify_status(mod, dst_reg->u.r16, - (int)i16, 1);
            dst_reg->u.r16 -= i16;
        }
        break;

    default:
        return -1;
    }
    return 0;
}

int x86_emu_cmp(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int32_t v;
    x86_emu_reg_t *dst_reg, *src_reg, src_imm = {0};

    switch (code[0])
    {
    case 0x3a:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        //todo:处理下KNOWN状态
        x86_emu_add_modify_status(mod,
            x86_emu_reg8_get(dst_reg, MODRM_GET_REG(code[1])),
            - (int32_t)x86_emu_reg8_get(src_reg, MODRM_GET_RM(code[1])), 1);
        break;

    case 0x3b:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));

        if (mod->inst.oper_size == 32)
        {
            x86_emu_add_modify_status(mod, dst_reg->u.r32, - (int32_t)src_reg->u.r32, 1);
        }
        else if (mod->inst.oper_size == 16)
        {
            x86_emu_add_modify_status(mod, dst_reg->u.r16, - (int16_t)src_reg->u.r16, 1);
        }
        break;

    case 0x3c:
        dst_reg = &mod->eax;
        if (dst_reg->known & 0xff)
        {
            x86_emu_add_modify_status(mod, dst_reg->u._r16.r8l, - (int32_t)code[1], 1);
        }
        break;

    case 0x3d:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, dst_reg))
        {
            v = x86_emu_dynam_le_read(mod->inst.oper_size, code + 2);
            if (mod->inst.oper_size == 32) 
            { 
                x86_emu_add_modify_status(mod, dst_reg->u.r32, - (int32_t)v, 1); 
            } 
            else if (mod->inst.oper_size == 16) 
            { 
                x86_emu_add_modify_status(mod, dst_reg->u.r16, - (int16_t)v, 1); 
            } 
        }
        break;

    case 0x80:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        if (X86_EMU_REG_H8_IS_KNOWN(dst_reg))
        {
            mod->inst.oper_size = 8;
            x86_emu_add_modify_status(mod, dst_reg->u._r16.r8h, - code[1], 1);
        }
        break;

    case 0x81:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, dst_reg))
        {
            if (mod->inst.oper_size == 32)
            {
                v = mbytes_read_int_little_endian_4b(code + 2);
                x86_emu_add_modify_status(mod, dst_reg->u.r32, - v, 1);
            }
            else if (mod->inst.oper_size == 16)
            {
                v = mbytes_read_int_little_endian_2b(code + 2);
                x86_emu_add_modify_status(mod, dst_reg->u.r16, - v, 1);
            }
        }
        break;

    default:
        return -1;
    }
    return 0;
}

int x86_emu_test_modify_status(struct x86_emu_mod *mod, uint32_t dst, uint32_t src)
{
    uint32_t t = dst & src;

    uint32_t sf = t & (1 << (mod->inst.oper_size - 1));

    x86_emu_sf_set(mod, sf);
    x86_emu_zf_set(mod, !t);
    x86_emu_of_set(mod, 0);
    x86_emu_cf_set(mod, 0);

    return 0;
}

int x86_emu_test(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int dst_type = -1;
    x86_emu_reg_t *dst_reg, *src_reg;
    switch (code[0])
    {
    case 0x84:
        x86_emu_test_modify_status(mod,
            x86_emu_reg_val_get2(mod, MODRM_GET_RM(code[1])),
            x86_emu_reg_val_get2(mod, MODRM_GET_REG(code[1])));
        break;

    case 0x85:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));

        x86_emu_test_modify_status(mod,
            x86_emu_reg_val_get(mod->inst.oper_size, dst_reg),
            x86_emu_reg_val_get(mod->inst.oper_size, src_reg));
        break;

        // 在操作数为8的情况下，访问EAX寄存器是访问AL
    case 0xa8:
        mod->inst.oper_size = 8;
        dst_type = OPERAND_TYPE_REG_EAX;
    case 0xa9:
        dst_type = OPERAND_TYPE_REG_EAX;
    case 0xf6:
        if (dst_type < 0)
        {
            mod->inst.oper_size = 8;
            dst_type = MODRM_GET_RM(code[1]);
        }

    case 0xf7:
        if (dst_type < 0) dst_type = MODRM_GET_RM(code[1]);
        x86_emu_test_modify_status(mod,
            x86_emu_reg_val_get2(mod, dst_type),
            x86_emu_dynam_le_read(mod->inst.oper_size, code + 2));
        break;

    default:
        return -1;
    }
    return 0;
}

int x86_emu_not(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    x86_emu_reg_t *dst_reg;
    uint8_t *dst8;

    switch (code[0])
    {
    case 0xf6:
        dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
        dst8[0] = ~dst8[0];
        break;

    case 0xf7:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, dst_reg))
        {
            // 这个函数调用的不怎么和规范， 实际上是利用了字符串的拼接规则对寄存器取反了
            // 后面的~，实际上不是=的一部分，而是dst_reg的一部分，~dst_reg
            x86_emu_dynam_oper(dst_reg, =~, dst_reg);
        }

        break;

    default:
        return -1;
    }

    return 0;
}

int x86_emu_mul(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    return -1;
}

int x86_emu_imul(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    return -1;
}

int x86_emu_div(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    return -1;
}

int x86_emu_idiv(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    return -1;
}

int x86_emu_movzx(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    x86_emu_reg_t *src_reg, *dst_reg;
    uint8_t *src8;
    x86_emu_operand_t src_imm;


    switch (code[0])
    {
    case 0xb6:
        memset(&src_imm, 0, sizeof (src_imm));
        x86_emu_modrm_analysis2(mod, code + 1, 0, NULL, NULL, &src_imm);
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        if (src_imm.kind == a_mem)
        {
            if (src_imm.u.mem.known == UINT_MAX)
            {
                x86_emu_dynam_set(dst_reg, (x86_emu_access_mem(mod, src_imm.u.mem.addr32))[0]);
            }
        }
        else
        {
            src8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
            if (mod->inst.oper_size == 32)
            {
                dst_reg->u.r32 = src8[0];
            }
            else if (mod->inst.oper_size == 16)
            {
                dst_reg->u.r16 = src8[0];
            }
        }
        break;

    case 0xb7:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));

        x86_emu_modrm_analysis2(mod, code + 1, 0, NULL, NULL, &src_imm);
        if (src_imm.kind == a_mem)
        {
            if (src_imm.u.mem.known == UINT_MAX)
            {
                uint8_t *new_addr = x86_emu_access_mem(mod, src_imm.u.mem.addr32);
                dst_reg->u.r32 = mbytes_read_int_little_endian_2b(new_addr);
            }
        }
        else
        {
            src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));

            dst_reg->u.r32 = src_reg->u.r16;
            dst_reg->known = 0xffffffff;
        }

        break;

    default:
        return -1;
    }
    return 0;
}

int x86_emu_cmovo(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *dst_reg, *src_reg;
    if (x86_emu_of_get(mod) == 1)
    {
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));

        x86_emu_dynam_oper(dst_reg, =, src_reg);
    }
    return 0;
}

int x86_emu_cmovno(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *dst_reg, *src_reg;
    if (!x86_emu_of_get(mod))
    {
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));

        x86_emu_dynam_oper(dst_reg, =, src_reg);
    }
    return 0;
}

int x86_emu_cmovnbe(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int cf, zf;
    x86_emu_reg_t *dst_reg, *src_reg;

    switch (code[0])
    {
    case 0x47:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (X86_EMU_EFLAGS_BIT_IS_KNOWN ((cf = x86_emu_cf_get(mod)))
            && X86_EMU_EFLAGS_BIT_IS_KNOWN((zf = x86_emu_zf_get(mod)))
            && X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, src_reg))
        {
            x86_emu_dynam_set(dst_reg, src_reg->u.r32);
        }
        break;

    default:
        return -1;
    }
    return 0;
}

#define bswap(_a, _b) \
    do { \
        uint8_t t = _a; \
        _a = _b; \
       _b = t; \
    } while(0)

#define bswap4b(_s) \
    do \
    {  \
        bswap((_s)[0], (_s)[3]); \
        bswap((_s)[1], (_s)[2]); \
    } while (0)

int x86_emu_bswap(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    x86_emu_reg_t *reg;
    uint8_t *s;

    switch (code[0])
    {
    case 0xc8:
    case 0xc9:
    case 0xca:
    case 0xcb:
    case 0xcc:
    case 0xcd:
    case 0xce:
    case 0xcf:
        reg = x86_emu_reg_get(mod, code[0] - 0xc8);
        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, reg))
        {
            if (mod->inst.oper_size == 32)
            {
                s = (uint8_t *)&reg->u.r32;
                bswap(s[0], s[3]);
                bswap(s[1], s[2]);
            }
            else if (mod->inst.oper_size == 16)
            {
                bswap(reg->u._r16.r8h, reg->u._r16.r8l);
            }
        }
        break;

    default:
        return -1;
    }
    return 0;
}

int x86_emu_clc(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    switch (code[0])
    {
    case 0xf8:
        x86_emu_cf_set(mod, 0);
        break;

    default:
        return -1;
    }
    return 0;
}

static int x86_emu_cld(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    x86_emu_df_set(mod, 0);
    return 0;
}

static int x86_emu_cmc(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    return x86_emu_cf_set(mod, !x86_emu_cf_get(mod));
}


static int x86_emu_dec(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *reg = NULL;
    int reg_type;
    uint8_t *dst8;

    switch (code[0])
    {
    case 0x48:
    case 0x49:
    case 0x4a:
    case 0x4b:
    case 0x4c:
    case 0x4d:
    case 0x4e:
    case 0x4f:
        reg = x86_emu_reg_get(mod, code[0] - 0x48);
    case 0xff:
        if (!reg)
            reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        x86_emu_dynam_oper_imm(reg, -=, 1);
        x86_emu_add_modify_status(mod, (mod->inst.oper_size == 32) ? reg->u.r32:reg->u.r16, -1, 1);
        break;

    case 0xfe:
        dst8 = x86_emu_reg8_get_ptr(mod, reg_type = MODRM_GET_RM(code[1]));
        x86_emu_add_modify_status(mod, dst8[0], -1, 1);
        dst8[0] -= 1;
        break;

    default:
        return -1;
    }
    return 0;
}

static int x86_emu_call(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    uint32_t known = UINT_MAX;
    uint64_t ret_addr;

    switch (code[0])
    {
    case 0xe8:
        ret_addr = (uint64_t)(code + len);
        x86_emu__push(mod, (uint8_t *)&known, (uint8_t *)&ret_addr, mod->word_size/8);
        break;

    default:
        return -1;
    }

    return 0;
}

static int x86_emu_jmp(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *reg;

    switch (code[0])
    {
    case 0xff:
        reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, reg))
        {
            mod->eip.known = UINT_MAX;
            mod->eip.u.r32 = reg->u.r32;

            if (mod->eip.u.r32 == X86_EMU_EXTERNAL_CALL)
            {
                mod->eip.u.r32 = mbytes_read_int_little_endian_4b(mod->stack.data + x86_emu_stack_top(mod));
                mod->eip.known = mbytes_read_int_little_endian_4b(mod->stack.known + x86_emu_stack_top(mod));
                x86_emu__pop(mod, 4);
            }
            return X86_EMU_UPDATE_EIP;
        }
        else
        {
            assert(0);
        }
        break;

        //这个地方不用出列别的jmp，所以不用返回-1
    }
    return 0;
}

static int x86_emu_ret(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    switch (code[0])
    {
    case 0xc3:
        mod->eip.u.r32 = mbytes_read_int_little_endian_4b(mod->stack.data + x86_emu_stack_top(mod));
        mod->eip.known = mbytes_read_int_little_endian_4b(mod->stack.known + x86_emu_stack_top(mod));
        x86_emu__pop(mod, 4);
        if (mod->eip.u.r32 == X86_EMU_EXTERNAL_CALL)
        { 
            printf("external call\n");
            mod->eip.u.r32 = mbytes_read_int_little_endian_4b(mod->stack.data + x86_emu_stack_top(mod));
            mod->eip.known = mbytes_read_int_little_endian_4b(mod->stack.known + x86_emu_stack_top(mod));
            x86_emu__pop(mod, 4);

            // todo:test
            mod->eax.u.r32 = 0x5c5aec40;
            mod->eax.known = UINT_MAX;
        }
        break;

    default:
        return -1;
    }
    return 0;
}

static int x86_emu_stc(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    switch (code[0])
    {
    case 0xf9:
        x86_emu_cf_set(mod, 1);
        break;

    default:
        return -1;
    }

    return 0;
}

static int x86_emu_callf(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    return -1;
}

static int x86_emu_inc(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *dst_reg = NULL;
    uint8_t *dst8;

    switch (code[0])
    {
    case 0x40: case 0x41: case 0x42: case 0x43:
    case 0x44: case 0x45: case 0x46: case 0x47:
        dst_reg = x86_emu_reg_get(mod, code[0] - 0x40);
    case 0xfe:
        if (code[0] == 0xfe)
            mod->inst.oper_size = 8;
    case 0xff:
        if (!dst_reg) dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (mod->inst.oper_size == 32)
        {
            x86_emu_add_modify_status(mod, dst_reg->u.r32, 1, 0);
            dst_reg->u.r32 += 1;
        }
        else if (mod->inst.oper_size == 16)
        {
            x86_emu_add_modify_status(mod, dst_reg->u.r16, 1, 0);
            dst_reg->u.r16 += 1;
        }
        else if (mod->inst.oper_size == 8)
        {
            dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
            x86_emu_add_modify_status(mod, dst8[0], 1, 0);
            dst8[0] += 1;
        }
        break;

    default:
        return -1;
    }

    return 0;
}

static int x86_emu_jmpf(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    return -1;
}

static int x86_emu_cbw(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    if (mod->inst.oper_size == 16)
    {
        mod->eax.u.r16 = (int16_t)(int8_t)(mod->eax.u._r16.r8l);
    }
    else
    {
        mod->eax.u.r32 = (int32_t)(int16_t)(mod->eax.u.r16);
    }
    return 0;
}

static int x86_emu_xchg(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *dst_reg = NULL, *src_reg = NULL;
    uint8_t *dst8, *src8;
    switch (code[0])
    {
    case 0x86:
        dst8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_RM(code[1]));
        src8 = x86_emu_reg8_get_ptr(mod, MODRM_GET_REG(code[1]));
        bswap(src8[0], dst8[0]);
        dst8 = x86_emu_reg8_get_known_ptr(mod, MODRM_GET_RM(code[1]));
        src8 = x86_emu_reg8_get_known_ptr(mod, MODRM_GET_REG(code[1]));
        bswap(src8[0], dst8[0]);
        break;

    case 0x87:
        if (!src_reg)
        {
            src_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
            dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        }
    case 0x91:
    case 0x92:
    case 0x93:
    case 0x94:
    case 0x95:
    case 0x96:
    case 0x97:
        if (!src_reg)
        {
            src_reg = &mod->eax;
            dst_reg = x86_emu_reg_get(mod, code[0] - 0x90);
        }
        if (mod->inst.oper_size == 32)
        {
            uint32_t t = dst_reg->u.r32;
            dst_reg->u.r32 = src_reg->u.r32;
            src_reg->u.r32 = t;
        }
        else if (mod->inst.oper_size == 16)
        {
            uint16_t t = dst_reg->u.r16;
            dst_reg->u.r16 = src_reg->u.r16;
            src_reg->u.r16 = t;
        }
        break;

    default:
        return -1;
    }
    return 0;
}

int ntz(uint32_t x) {
    unsigned y;
    int n;
    if (x == 0) return 32;
    n = 31;
    y = x << 16; if (y != 0) { n = n - 16; x = y; }
    y = x << 8; if (y != 0) { n = n - 8; x = y; }
    y = x << 4; if (y != 0) { n = n - 4; x = y; }
    y = x << 2; if (y != 0) { n = n - 2; x = y; }
    y = x << 1; if (y != 0) { n = n - 1; }
    return n;
}

static int x86_emu_bsf(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    x86_emu_reg_t *src_reg, *dst_reg;
    switch (code[0])
    {
    case 0xbc:
        src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, src_reg))
        {
            uint32_t v = x86_emu_reg_val_get(mod->inst.oper_size, src_reg);
            if (v)
            {
                x86_emu_zf_set(mod, 0);
                if (mod->inst.oper_size == 16)
                {
                    dst_reg->known |= 0xffff;
                    dst_reg->u.r16 = ntz(src_reg->u.r16);
                }
                else
                {
                    dst_reg->known |= UINT_MAX;
                    dst_reg->u.r32 = ntz(src_reg->u.r32);
                }
            }
            else
            {
                x86_emu_zf_set(mod, 1);
            }
        }
        break;

    default:
        return -1;
    }
    return 0;
}


static int x86_emu_btr(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *dst_reg, *src_reg;
    switch (code[0])
    {
    case 0xb3:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        if (mod->inst.oper_size == 32)
        {
            x86_emu_cf_set(mod, X86_EMU_BIT(dst_reg->u.r32, src_reg->u.r32 & 0x1f));
            X86_EMU_BIT_CLEAR(dst_reg->u.r32, src_reg->u.r32 & 0x1f);
        }
        else
        {
            x86_emu_cf_set(mod, X86_EMU_BIT(dst_reg->u.r16, src_reg->u.r16 & 0x0f));
            X86_EMU_BIT_CLEAR(dst_reg->u.r16, src_reg->u.r16 & 0x0f);
        }
        break;

    case 0xba:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (mod->inst.oper_size == 32)
        {
            x86_emu_cf_set(mod, X86_EMU_BIT(dst_reg->u.r32, code[2] & 0x1f));
            X86_EMU_BIT_CLEAR(dst_reg->u.r32, code[2] & 0x1f);
        }
        else
        {
            x86_emu_cf_set(mod, X86_EMU_BIT(dst_reg->u.r16, code[2] & 0x0f));
            X86_EMU_BIT_CLEAR(dst_reg->u.r16, code[2] & 0x0f);
        }
        break;

    default:
        return -1;
    }
    return 0;
}

static int x86_emu_jnbe(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    switch (code[0])
    {
    case 0x87:
        if ((x86_emu_cf_get(mod) == 0) && (x86_emu_zf_get(mod) == 0))
        {
            mod->eip.u.r32 = (((uint64_t) mod->inst.start) & UINT_MAX)
                + mod->inst.len + x86_emu_dynam_le_read(mod->inst.oper_size, code + 1);
            mod->eip.known = UINT_MAX;
            mod->inst.is_fa = 1;
            return X86_EMU_UPDATE_EIP;
        }
        break;

    default:
        return -1;
    }
    return 0;
}

static int x86_emu_cdq(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    // cdq
    if (mod->inst.oper_size == 32)
    {
        if (mod->eax.u.r32 & 0x80000000)
        {
            mod->edx.u.r32 = UINT_MAX;
        }
    }
    // cwd
    else if (mod->inst.oper_size == 16)
    {
        if (mod->eax.u.r16 & 0x8000)
        {
            mod->edx.u.r16 = 0xffff;
        }
    }
    return 0;
}

static int x86_emu_movsb(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int cts, i;
    uint8_t *dst, *src;

    if (mod->inst.rep)
    { 
        cts = (mod->inst.oper_size == 32) ? mod->ecx.u.r32:mod->ecx.u.r16;
    }
    else
    {
        cts = 1;
    }

    dst = x86_emu_mem_fix(mod->edi.u.r32);
    src = x86_emu_mem_fix(mod->esi.u.r32);

    for (i = 0; cts; cts--, i++)
    {
        printf("[%02x], ", src[i]);
        dst[i] = src[i];
    }
    printf("\n");

    return 0;
}

static int x86_emu_pop(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *dst_reg;
    x86_emu_operand_t src_imm;

    switch (code[0])
    {
    case 0x58:
    case 0x59:
    case 0x5a:
    case 0x5b:
    case 0x5c:
    case 0x5d:
    case 0x5e:
    case 0x5f:
        dst_reg = x86_emu_reg_get(mod, code[0] - 0x58);
        if (mod->inst.oper_size == 32)
        {
            dst_reg->u.r32 = mbytes_read_int_little_endian_4b(mod->stack.data + x86_emu_stack_top(mod));
            dst_reg->known = mbytes_read_int_little_endian_4b(mod->stack.known + x86_emu_stack_top(mod));
            x86_emu__pop(mod, 4);
        }
        else
        {
            dst_reg->u.r16 = mbytes_read_int_little_endian_2b(mod->stack.data + x86_emu_stack_top(mod));
            dst_reg->known |= mbytes_read_int_little_endian_2b(mod->stack.known + x86_emu_stack_top(mod));
            x86_emu__pop(mod, 2);
        }
        break;

    case 0x8f:
        memset(&src_imm, 0, sizeof (src_imm));
        x86_emu_modrm_analysis2(mod, code + 1, 0, NULL, NULL, &src_imm);
        if (src_imm.kind == a_mem)
        {
            assert(src_imm.u.mem.addr32);
            assert(src_imm.u.mem.known);
            uint8_t *new_addr = x86_emu_access_mem(mod, src_imm.u.mem.addr32);

            memcpy(new_addr, mod->stack.data + x86_emu_stack_top(mod),  mod->inst.oper_size / 8);
            x86_emu__pop(mod, mod->inst.oper_size / 8);
        }
        else
        {
            assert(0);
        }
        break;

    default:
        return -1;
    }
    return 0;
}

static int x86_emu_lahf(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    mod->eax.u._r16.r8l = (uint8_t)mod->eflags.eflags;
    return 0;
}

static inline int x86_emu_inst_init(struct x86_emu_mod *mod, uint8_t *inst, int len)
{
    mod->inst.oper_size = 32;
    mod->inst.start = inst;
    mod->inst.len = len;
    mod->inst.rep = 0;
    mod->inst.is_fa = 0;

    return 0;
}

struct x86_emu_on_inst_item x86_emu_inst_tab[] =
{
    { {0x02, 0, 0}, -1, x86_emu_add },
    { {0x03, 0, 0}, -1, x86_emu_add },
    { {0x04, 0, 0}, -1, x86_emu_add },
    { {0x05, 0, 0}, -1, x86_emu_add },
    { {0x0a, 0, 0}, -1, x86_emu_or },
    { {0x0b, 0, 0}, -1, x86_emu_or },
    { {0x0d, 0, 0}, -1, x86_emu_or },
    { {0x12, 0, 0}, -1, x86_emu_adc },
    { {0x13, 0, 0}, -1, x86_emu_adc },
    { {0x1b, 0, 0}, -1, x86_emu_sbb },
    { {0x1d, 0, 0}, -1, x86_emu_sbb },
    { {0x22, 0, 0}, -1, x86_emu_and },
    { {0x23, 0, 0}, -1, x86_emu_and },
    { {0x25, 0, 0}, -1, x86_emu_and },
    { {0x2b, 0, 0}, -1, x86_emu_sub },
    { {0x2c, 0, 0}, -1, x86_emu_sub },
    { {0x2d, 0, 0}, -1, x86_emu_sub },
    { {0x3a, 0, 0}, -1, x86_emu_cmp },
    { {0x3c, 0, 0}, -1, x86_emu_cmp },
    { {0x32, 0, 0}, -1, x86_emu_xor },
    { {0x33, 0, 0}, -1, x86_emu_xor },
    { {0x34, 0, 0}, -1, x86_emu_xor },
    { {0x35, 0, 0}, -1, x86_emu_xor },
    { {0x3b, 0, 0}, -1, x86_emu_cmp },
    { {0x3d, 0, 0}, -1, x86_emu_cmp },
    { {0x40, 0, 0}, -1, x86_emu_inc },
    { {0x41, 0, 0}, -1, x86_emu_inc },
    { {0x42, 0, 0}, -1, x86_emu_inc },
    { {0x43, 0, 0}, -1, x86_emu_inc },
    { {0x44, 0, 0}, -1, x86_emu_inc },
    { {0x45, 0, 0}, -1, x86_emu_inc },
    { {0x46, 0, 0}, -1, x86_emu_inc },
    { {0x47, 0, 0}, -1, x86_emu_inc },
    { {0x48, 0, 0}, -1, x86_emu_dec },
    { {0x49, 0, 0}, -1, x86_emu_dec },
    { {0x4a, 0, 0}, -1, x86_emu_dec },
    { {0x4b, 0, 0}, -1, x86_emu_dec },
    { {0x4c, 0, 0}, -1, x86_emu_dec },
    { {0x4d, 0, 0}, -1, x86_emu_dec },
    { {0x4e, 0, 0}, -1, x86_emu_dec },
    { {0x4f, 0, 0}, -1, x86_emu_dec },
    { {0x50, 0, 0}, -1, x86_emu_push },
    { {0x51, 0, 0}, -1, x86_emu_push },
    { {0x52, 0, 0}, -1, x86_emu_push },
    { {0x53, 0, 0}, -1, x86_emu_push },
    { {0x55, 0, 0}, -1, x86_emu_push },
    { {0x56, 0, 0}, -1, x86_emu_push },
    { {0x57, 0, 0}, -1, x86_emu_push },
    { {0x58, 0, 0}, -1, x86_emu_pop },
    { {0x59, 0, 0}, -1, x86_emu_pop },
    { {0x5a, 0, 0}, -1, x86_emu_pop },
    { {0x5b, 0, 0}, -1, x86_emu_pop },
    { {0x5c, 0, 0}, -1, x86_emu_pop },
    { {0x5d, 0, 0}, -1, x86_emu_pop },
    { {0x5e, 0, 0}, -1, x86_emu_pop },
    { {0x5f, 0, 0}, -1, x86_emu_pop },
    { {0x68, 0, 0}, -1, x86_emu_push },
    { {0x80, 0, 0}, 0, x86_emu_add },
    { {0x80, 0, 0}, 1, x86_emu_or },
    { {0x80, 0, 0}, 2, x86_emu_adc },
    { {0x80, 0, 0}, 3, x86_emu_sbb },
    { {0x80, 0, 0}, 4, x86_emu_and },
    { {0x80, 0, 0}, 5, x86_emu_sub },
    { {0x80, 0, 0}, 6, x86_emu_xor },
    { {0x80, 0, 0}, 7, x86_emu_cmp },
    { {0x81, 0, 0}, 0, x86_emu_add },
    { {0x81, 0, 0}, 1, x86_emu_or },
    { {0x81, 0, 0}, 2, x86_emu_adc },
    { {0x81, 0, 0}, 3, x86_emu_sbb },
    { {0x81, 0, 0}, 4, x86_emu_and },
    { {0x81, 0, 0}, 5, x86_emu_sub },
    { {0x81, 0, 0}, 6, x86_emu_xor },
    { {0x81, 0, 0}, 7, x86_emu_cmp },
    { {0x84, 0, 0}, -1, x86_emu_test },
    { {0x85, 0, 0}, -1, x86_emu_test },
    { {0x86, 0, 0}, -1, x86_emu_xchg },
    { {0x87, 0, 0}, -1, x86_emu_xchg },
    { {0x88, 0, 0}, -1, x86_emu_mov },
    { {0x89, 0, 0}, -1, x86_emu_mov },
    // xchg的指令格式其中一个是 90 + rw，因为xchg eax, eax，
    // 是不做任何改动，所以逻辑上来说 xchg eax, eax == nop
    { {0x90, 0, 0}, -1, x86_emu_nop },
    { {0x91, 0, 0}, -1, x86_emu_xchg },
    { {0x92, 0, 0}, -1, x86_emu_xchg },
    { {0x93, 0, 0}, -1, x86_emu_xchg },
    { {0x94, 0, 0}, -1, x86_emu_xchg },
    { {0x95, 0, 0}, -1, x86_emu_xchg },
    { {0x96, 0, 0}, -1, x86_emu_xchg },
    { {0x97, 0, 0}, -1, x86_emu_xchg },
    { {0x91, 0, 0}, -1, x86_emu_nop },
    { {0x8a, 0, 0}, -1, x86_emu_mov },
    { {0x8b, 0, 0}, -1, x86_emu_mov },
    { {0x8d, 0, 0}, -1, x86_emu_lea },
    { {0x8f, 0, 0}, -1, x86_emu_pop },
    { {0x9f, 0, 0}, -1, x86_emu_lahf },
    { {0xb0, 0, 0}, -1, x86_emu_mov },
    { {0xb1, 0, 0}, -1, x86_emu_mov },
    { {0xb2, 0, 0}, -1, x86_emu_mov },
    { {0xb3, 0, 0}, -1, x86_emu_mov },
    { {0xb4, 0, 0}, -1, x86_emu_mov },
    { {0xb5, 0, 0}, -1, x86_emu_mov },
    { {0xb6, 0, 0}, -1, x86_emu_mov },
    { {0xb7, 0, 0}, -1, x86_emu_mov },
    { {0xb8, 0, 0}, -1, x86_emu_mov },
    { {0xb9, 0, 0}, -1, x86_emu_mov },
    { {0xba, 0, 0}, -1, x86_emu_mov },
    { {0xbb, 0, 0}, -1, x86_emu_mov },
    { {0xbc, 0, 0}, -1, x86_emu_mov },
    { {0xbd, 0, 0}, -1, x86_emu_mov },
    { {0xbe, 0, 0}, -1, x86_emu_mov },
    { {0xbf, 0, 0}, -1, x86_emu_mov },
    { {0x98, 0, 0}, -1, x86_emu_cbw },
    { {0x9c, 0, 0}, -1, x86_emu_pushfd },
    { {0x9d, 0, 0}, -1, x86_emu_popfd },
    { {0x99, 0, 0}, -1, x86_emu_cdq },
    { {0xa4, 0, 0}, -1, x86_emu_movsb },
    { {0xa8, 0, 0}, -1, x86_emu_test },
    { {0xa9, 0, 0}, -1, x86_emu_test },
    { {0xb9, 0, 0}, -1, x86_emu_mov },
    { {0xc0, 0, 0}, 0, x86_emu_rol },
    { {0xc0, 0, 0}, 2, x86_emu_rcl },
    { {0xc0, 0, 0}, 4, x86_emu_shl },
    { {0xc1, 0, 0}, 0, x86_emu_rol },
    { {0xc1, 0, 0}, 1, x86_emu_ror },
    { {0xc1, 0, 0}, 2, x86_emu_rcl },
    { {0xc1, 0, 0}, 3, x86_emu_rcr },
    { {0xc1, 0, 0}, 4, x86_emu_shl },
    { {0xc1, 0, 0}, 5, x86_emu_shr },
    { {0xc1, 0, 0}, 6, x86_emu_shl },
    { {0xc6, 0, 0}, 0, x86_emu_mov },
    { {0xc3, 0, 0}, -1, x86_emu_ret },
    { {0xd0, 0, 0}, 0, x86_emu_rol },
    { {0xd0, 0, 0}, 1, x86_emu_ror },
    { {0xd0, 0, 0}, 2, x86_emu_rcl },
    { {0xd0, 0, 0}, 3, x86_emu_rcr },
    { {0xd1, 0, 0}, 0, x86_emu_rol },
    { {0xd1, 0, 0}, 1, x86_emu_ror },
    { {0xd1, 0, 0}, 2, x86_emu_rcl },
    { {0xd1, 0, 0}, 3, x86_emu_rcr },
    { {0xd1, 0, 0}, 4, x86_emu_shl },
    { {0xd1, 0, 0}, 5, x86_emu_shr },
    { {0xd1, 0, 0}, 6, x86_emu_shl },
    { {0xd1, 0, 0}, 7, x86_emu_sar },
    { {0xd2, 0, 0}, 4, x86_emu_shl },
    { {0xd2, 0, 0}, 0, x86_emu_rol },
    { {0xd2, 0, 0}, 1, x86_emu_ror },
    { {0xd2, 0, 0}, 2, x86_emu_rcl },
    { {0xd2, 0, 0}, 3, x86_emu_rcr },
    { {0xd2, 0, 0}, 4, x86_emu_shl },
    { {0xd2, 0, 0}, 5, x86_emu_shr },
    { {0xd3, 0, 0}, 0, x86_emu_rol },
    { {0xd3, 0, 0}, 1, x86_emu_ror },
    { {0xd3, 0, 0}, 2, x86_emu_rcl },
    { {0xd3, 0, 0}, 3, x86_emu_rcr },
    { {0xd3, 0, 0}, 4, x86_emu_shl },
    { {0xd3, 0, 0}, 5, x86_emu_shr },
    //{ {0xd3, 0, 0}, 6, x86_emu_shl },
    { {0xd3, 0, 0}, 7, x86_emu_sar },
    { {0xe8, 0, 0}, -1, x86_emu_call },
    { {0xe9, 0, 0}, -1, x86_emu_jmp },
    { {0xf5, 0, 0}, -1, x86_emu_cmc },
    { {0xf6, 0, 0}, 0, x86_emu_test },
    { {0xf6, 0, 0}, 1, x86_emu_test },
    { {0xf6, 0, 0}, 2, x86_emu_not },
    { {0xf6, 0, 0}, 3, x86_emu_neg },
    { {0xf6, 0, 0}, 4, x86_emu_mul },
    { {0xf6, 0, 0}, 5, x86_emu_imul },
    { {0xf6, 0, 0}, 6, x86_emu_div },
    { {0xf6, 0, 0}, 7, x86_emu_idiv },
    { {0xf7, 0, 0}, 0, x86_emu_test },
    { {0xf7, 0, 0}, 1, x86_emu_test },
    { {0xf7, 0, 0}, 2, x86_emu_not },
    { {0xf7, 0, 0}, 3, x86_emu_neg },
    { {0xf7, 0, 0}, 4, x86_emu_mul },
    { {0xf7, 0, 0}, 5, x86_emu_imul },
    { {0xf7, 0, 0}, 6, x86_emu_div },
    { {0xf7, 0, 0}, 7, x86_emu_idiv },
    { {0xf8, 0, 0}, -1, x86_emu_clc },
    { {0xf9, 0, 0}, -1, x86_emu_stc },
    { {0xfc, 0, 0}, -1, x86_emu_cld },
    { {0xfe, 0, 0}, 1, x86_emu_dec },
    { {0xfe, 0, 0}, 0, x86_emu_inc },
    { {0xff, 0, 0}, 0, x86_emu_inc },
    { {0xff, 0, 0}, 1, x86_emu_dec },
    { {0xff, 0, 0}, 2, x86_emu_call },
    { {0xff, 0, 0}, 3, x86_emu_callf },
    { {0xff, 0, 0}, 4, x86_emu_jmp },
    { {0xff, 0, 0}, 5, x86_emu_jmpf },
    { {0xff, 0, 0}, 6, x86_emu_push },
    { {0xff, 0, 0}, 7, x86_emu_push },

    { {0x0f, 0x40, 0}, -1, x86_emu_cmovo },
    { {0x0f, 0x41, 0}, -1, x86_emu_cmovno },
    { {0x0f, 0x47, 0}, -1, x86_emu_cmovnbe },
    { {0x0f, 0x48, 0}, -1, x86_emu_cmovs },
    { {0x0f, 0x4a, 0}, -1, x86_emu_cmovp },
    { {0x0f, 0x4c, 0}, -1, x86_emu_cmovl },
    { {0x0f, 0x87, 0}, -1, x86_emu_jnbe },
    { {0x0f, 0x94, 0}, -1, x86_emu_setz },
    { {0x0f, 0x95, 0}, -1, x86_emu_setnz },
    { {0x0f, 0x9a, 0}, -1, x86_emu_setp },
    { {0x0f, 0xab, 0}, -1, x86_emu_bts },
    { {0x0f, 0xac, 0}, -1, x86_emu_shrd },
    { {0x0f, 0xa3, 0}, -1, x86_emu_bt },
    { {0x0f, 0xb3, 0}, -1, x86_emu_btr },
    { {0x0f, 0xb6, 0}, -1, x86_emu_movzx },
    { {0x0f, 0xb7, 0}, -1, x86_emu_movzx },
    { {0x0f, 0xba, 0}, 4,  x86_emu_bt },
    { {0x0f, 0xba, 0}, 6,  x86_emu_btr },
    { {0x0f, 0xba, 0}, 7,  x86_emu_btc },
    { {0x0f, 0xbb, 0}, -1, x86_emu_btc },
    { {0x0f, 0xbc, 0}, -1, x86_emu_bsf },
    { {0x0f, 0xbe, 0}, -1, x86_emu_movsx },
    { {0x0f, 0xbf, 0}, -1, x86_emu_movsx },
    { {0x0f, 0xc1, 0}, -1, x86_emu_xadd },
    { {0x0f, 0xc8, 0}, -1, x86_emu_bswap },
    { {0x0f, 0xc9, 0}, -1, x86_emu_bswap },
    { {0x0f, 0xca, 0}, -1, x86_emu_bswap },
    { {0x0f, 0xcb, 0}, -1, x86_emu_bswap },
    { {0x0f, 0xcc, 0}, -1, x86_emu_bswap },
    { {0x0f, 0xcd, 0}, -1, x86_emu_bswap },
    { {0x0f, 0xce, 0}, -1, x86_emu_bswap },
    { {0x0f, 0xcf, 0}, -1, x86_emu_bswap },

    { {0, 0, 0}, -1, NULL},
};

int x86_emu_dump (struct x86_emu_mod *mod)
{
#if 0
    if (mod->inst.count == 5035)
    {
        mod->eflags.eflags = 0x206;
        mod->eflags.known = UINT_MAX;
    }
#endif
    // todo:调试代码
    // vmp_jmp 1244出错，指令45288
    // vmp_jmp 1217
    // inst[41522]的eax看起来会受eflags的影响
#if 0
    if (mod->inst.count == 41522)
    {
        mod->eax.u.r32 = 0x213;
    }
#endif

    printf("EAX[%08x:%08x], EBX[%08x:%08x], ECX[%08x:%08x], EDX[%08x], [%d][stack size = %d]\n"
        "EDI[%08x:%08x], ESI[%08x:%08x], EBP[%08x:%08x], ESP[%08x], EIP[%08x], EF[%08x], CF[%d], ZF[%d], OF[%d], SF[%d]\n",
        mod->eax.known, mod->eax.u.r32, mod->ebx.known, mod->ebx.u.r32,
        mod->ecx.known, mod->ecx.u.r32, mod->edx.u.r32, mod->inst.count + 1, mod->stack.size - x86_emu_stack_top(mod),
        mod->edi.known, mod->edi.u.r32, mod->esi.known, mod->esi.u.r32,
        mod->ebp.known, mod->ebp.u.r32, mod->esp.u.r32, mod->eip.u.r32,
        mod->eflags.eflags, x86_emu_cf_get(mod), x86_emu_zf_get(mod), x86_emu_of_get(mod), x86_emu_sf_get(mod));


#if 0
        static uint8_t *watch_addr = NULL;
    if (mod->inst.count == 1244)
    {
        if (!watch_addr)
            watch_addr = x86_emu_access_mem(mod, mod->ebp.u.r32);
    }

        if (watch_addr)
        {
        printf("[ebp] = [%x]\n", mbytes_read_int_little_endian_4b(watch_addr));
        }
#endif

#if 0
    uint8_t *stack_start, *stack_end;
    int cts;

    // 四字节地址对齐
    stack_start = (uint8_t *)(mod->addr64_prefix | (uint64_t)(mod->esp.u.r32 & ~3));
    stack_end = mod->stack.data + mod->stack.size;

    for (cts = 0; stack_start < stack_end; stack_start += 4, cts++)
    {
        printf("[%08x]", *((uint32_t *)stack_start));
        if ((cts + 1) % 8 == 0)
        {
            printf("\n");
        }
    }
    printf("\n===============\n");
#endif

    return 0;
}

int x86_emu_run(struct x86_emu_mod *mod, uint8_t *addr, int len)
{
    int code_i = 1, ret = -1;
    struct x86_emu_on_inst_item *array = x86_emu_inst_tab;

    x86_emu_inst_init(mod, addr, len);

    mod->inst.count++;

    // x86模拟器的主循环需要对指令集比较深厚的理解
    // 英文注释直接超自白皮书，这样可以减少查询的工作量，大家可以放心观看
    // 中文注释来自于作者

    // Instruction prefixes are divided into four groups, each with a set of allowable prefix codex.
    // For each instruction, it is only useful to include up to one prefix code from each of the four
    // groups (Groups 1, 2, 3, 4).
    switch (addr[0])
    {
        // 修改段寄存器为ss，一般来说不影响，因为默认段寄存器就是ss
    case 0x36:
        break;

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
        mod->inst.rep = 1;
        break;

    default:
        code_i = 0;
        break;
    }

    for (; array->opcode[0]; array++)
    {
        if ((array->opcode[0] != addr[code_i])
            || (array->opcode[1] && (array->opcode[1] != addr[code_i + 1])))
            continue;

        if (array->opcode[1])
            code_i++;

        if ((array->reg != -1))
        {
            if (MODRM_GET_REG(addr[code_i + 1]) == array->reg)
            {
                ret = array->on_inst(mod, addr + code_i, len - code_i);
                break;
            }
        }
        else
        {
            ret = array->on_inst(mod, addr + code_i, len - code_i);
            break;
        }
    }

    if (!array->opcode[0] || (ret == -1))
    {
        print_err ("[%s] err: meet un-support instruction. %s:%d\r\n", time2s (0), __FILE__, __LINE__);
        return -1;
    }

    x86_emu_dump (mod);

    return ret;
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
static int x86_emu_modrm_analysis2(struct x86_emu_mod *mod, uint8_t *cur,
    int oper_size1, int *dst_type1, int *src_type1, x86_emu_operand_t *operand1)
{
    uint8_t modrm = cur[0];
    uint32_t v32 = 0;
    x86_emu_reg_t *reg, *base_reg, *index_reg = NULL, *rm_reg;
    int oper_size = oper_size1 ? oper_size1 : mod->inst.oper_size;
    x86_emu_operand_t imm;
    memset(&imm, 0, sizeof (imm));

    int mod1 = MODRM_GET_MOD(modrm);
    int rm1 = MODRM_GET_RM(modrm);
    int reg1 = MODRM_GET_REG(modrm);
    int scale = 0, index = 0, base = 0;

    reg = x86_emu_reg_get(mod, reg1);
    rm_reg = x86_emu_reg_get(mod, rm1);

    switch (mod1)
    {
    case 0:
        imm.kind = a_mem;
        imm.u.mem.known = UINT32_MAX;

        if (rm1 == 0b101)
        {
            imm.u.mem.addr32 = mbytes_read_int_little_endian_4b(cur + 1);
        }
        else if (rm1 == 0b100)
        {
            goto X86_EMU_SIB_LABEL;
        }
        else
        {
            imm.u.mem.addr32 = rm_reg->u.r32;
        }
            printf("debug: addr32= %x\n", imm.u.mem.addr32);
        break;

        // MODRM中MOD为0b01, 0b11处理基本是一样的，除了操作的立即数
    case 1:
    case 2:
X86_EMU_SIB_LABEL:
        imm.kind = a_mem;
        if (rm1 == OPERAND_TYPE_REG_ESP)
        { // follow SIB
            scale = SIB_GET_SCALE(cur[1]);
            index = SIB_GET_INDEX(cur[1]);
            base = SIB_GET_BASE(cur[1]);

            if (mod1)
            {
                v32 = (mod1 == 0b10)?mbytes_read_int_little_endian_4b(cur + 2):((int8_t)cur[2]);
            }

            base_reg = x86_emu_reg_get(mod, base);
            if (index != 4)
            {
                index_reg = x86_emu_reg_get(mod, index);
            }

            if (base == 0b101)
            {
                imm.u.mem.known = base_reg->known & UINT32_MAX;
                imm.u.mem.addr32 = base_reg->u.r32 + scale + v32;
            }
            else
            {
                imm.u.mem.known = base_reg->known & (index_reg?index_reg->known:UINT32_MAX);
                //imm.u.mem.addr32 = base_reg->u.r32 + (index_reg?index_reg->u.r32:0)*(index^scale) + v32;
                imm.u.mem.addr32 = base_reg->u.r32 + (index_reg?index_reg->u.r32:0)*(1 << scale) + v32;
            }
        }
        else  if (mod1 == 0b10)
        {
            v32 = mbytes_read_int_little_endian_4b(cur + 1);
            imm.u.mem.known = UINT_MAX & rm_reg->known;
            imm.u.mem.addr32 = rm_reg->u.r32 + v32;
        }
        else if (mod1 == 0b01)
        {
            imm.u.mem.known = UINT_MAX & rm_reg->known;
            imm.u.mem.addr32 = rm_reg->u.r32 + cur[1];
        }
            printf("debug: addr32= %x,\n", imm.u.mem.addr32);
        break;

    case 3:
        imm.kind = a_reg32;
        imm.u.reg = *reg;
        break;
    }

    if (src_type1)      *src_type1 = reg1;
    if (dst_type1)      *dst_type1 = MODRM_GET_RM(modrm);
    if (operand1)       *operand1 = imm;

    return 0;
}

static struct x86_emu_reg *x86_emu_reg_get(struct x86_emu_mod *mod, int reg_type)
{
    x86_emu_reg_t *regs = &mod->eax;
    int i;

    if (mod->inst.oper_size == 8)
    {
        return regs + reg_type % 4;
    }
    else
    {
        for (i = 0; i < 8; i++)
        {
            if (regs[i].type == reg_type)
            {
                return regs + i;
            }
        }
    }

    printf("x86_emu_reg_get(, %d) meet un-support reg_type. %s:%d\r\n", reg_type, __FILE__, __LINE__);

    return NULL;
}

static int x86_emu_cf_set(struct x86_emu_mod *mod, uint32_t v)
{
    XE_EFLAGS_SET(mod->eflags, XE_EFLAGS_CF, v);
    return 0;
}

static int x86_emu_cf_get(struct x86_emu_mod *mod)
{
    return XE_EFLAGS_BIT_GET(mod, XE_EFLAGS_CF);
}

static int x86_emu_pf_set(struct x86_emu_mod *mod, int v)
{
    XE_EFLAGS_SET(mod->eflags, XE_EFLAGS_PF, v);
    return 0;
}

static int x86_emu_pf_get(struct x86_emu_mod *mod)
{
    return XE_EFLAGS_BIT_GET(mod, XE_EFLAGS_PF);
}

static int x86_emu_af_set(struct x86_emu_mod *mod, int v)
{
    XE_EFLAGS_SET(mod->eflags, XE_EFLAGS_AF, v);
    return 0;
}

static int x86_emu_af_get(struct x86_emu_mod *mod)
{
    return XE_EFLAGS_BIT_GET(mod, XE_EFLAGS_AF);
}

static int x86_emu_zf_set(struct x86_emu_mod *mod, int v)
{
    XE_EFLAGS_SET(mod->eflags, XE_EFLAGS_ZF, v);
    return 0;
}

static int x86_emu_zf_get(struct x86_emu_mod *mod)
{
    return XE_EFLAGS_BIT_GET(mod, XE_EFLAGS_ZF);
}

static int x86_emu_sf_set(struct x86_emu_mod *mod, int v)
{
    XE_EFLAGS_SET(mod->eflags, XE_EFLAGS_SF, v);
    return 0;
}

static int x86_emu_sf_get(struct x86_emu_mod *mod)
{
    return XE_EFLAGS_BIT_GET(mod, XE_EFLAGS_SF);
}

static int x86_emu_tf_set(struct x86_emu_mod *mod, int v)
{
    XE_EFLAGS_SET(mod->eflags, XE_EFLAGS_TF, v);
    return 0;
}

static int x86_emu_tf_get(struct x86_emu_mod *mod)
{
    return XE_EFLAGS_BIT_GET(mod, XE_EFLAGS_TF);
}

static int x86_emu_ief_set(struct x86_emu_mod *mod, int v)
{
    XE_EFLAGS_SET(mod->eflags, XE_EFLAGS_IEF, v);
    return 0;
}

static int x86_emu_ief_get(struct x86_emu_mod *mod)
{
    return XE_EFLAGS_BIT_GET(mod, XE_EFLAGS_IEF);
}

static int x86_emu_df_get(struct x86_emu_mod *mod)
{
    return XE_EFLAGS_BIT_GET(mod, XE_EFLAGS_DF);
}

static int x86_emu_df_set(struct x86_emu_mod *mod, int v)
{
    XE_EFLAGS_SET(mod->eflags, XE_EFLAGS_DF, v);
    return 0;
}

static int x86_emu_of_get(struct x86_emu_mod *mod)
{
    return XE_EFLAGS_BIT_GET(mod, XE_EFLAGS_DF);
}

static int x86_emu_of_set(struct x86_emu_mod *mod, int v)
{
    XE_EFLAGS_SET(mod->eflags, XE_EFLAGS_OF, v);
    return 0;
}

static uint32_t x86_emu_reg_val_get(int oper_siz, struct x86_emu_reg *reg)
{
    switch (oper_siz/8)
    {
    case 1:
        return reg->u._r16.r8l;

    case 2:
        return reg->u.r16;

    case 4:
        return reg->u.r32;
    }

    return 0;
}

static  uint32_t x86_emu_reg_val_get2(struct x86_emu_mod *mod, int reg_type)
{
    struct x86_emu_reg *reg, *regs = &mod->eax;

    switch (mod->inst.oper_size)
    {
    case 8:
        reg = &regs[reg_type % 4];
        return (reg_type < 4)?reg->u._r16.r8l:reg->u._r16.r8h;

    case 16:
        reg = &regs[reg_type];
        return reg->u.r16;

    case 32:
        reg = &regs[reg_type];
        return reg->u.r32;

    default:
        assert(0);
        break;
    }

    return 0;
}

static int x86_emu__push_reg(struct x86_emu_mod *mod, int oper_siz1, struct x86_emu_reg *reg)
{
    int oper_siz = oper_siz1 ? oper_siz1 : mod->inst.oper_size;

    assert(oper_siz / 8);

    return x86_emu__push(mod, (uint8_t *)&reg->known, (uint8_t *)&reg->u._r16.r8l, oper_siz / 8);
}

static int x86_emu__push_imm8(struct x86_emu_mod *mod, uint8_t imm8)
{
    uint8_t known = 0xff;
    return x86_emu__push(mod, &known, &imm8, 1);
}

static int x86_emu__push_imm16(struct x86_emu_mod *mod, uint16_t imm16)
{
    uint16_t known = 0xffff;
    return x86_emu__push(mod, (uint8_t *)&known, (uint8_t *)&imm16, sizeof (imm16));
}

static int x86_emu__push_imm32(struct x86_emu_mod *mod, uint32_t imm32)
{
    uint32_t known = UINT_MAX;
    return x86_emu__push (mod, (uint8_t *)&known, (uint8_t *)&imm32, sizeof (imm32));
}

#define FAKE_IMAGE_BASE          0x400000

static uint8_t *x86_emu_access_mem(struct x86_emu_mod *mod, uint32_t va)
{
    uint8_t *new_addr = NULL;
    uint8_t *t_addr = NULL;
    char sym_name[128];

    // 在CPU的模拟器内部，暂时有以下几种类型的地址
    // 1. 堆栈内的地址，访问堆栈时需要使用
    // 2. PE文件内的地址，jmp时需要
    // 3. 访问到了IAT地址，比如访问time()，那么这个地址在IAT表内

    // 可能是内部的地址
    if ((va & 0xffC00000) == FAKE_IMAGE_BASE)
    {
        // 假如我们访问到了一个地址，这个地址是IAT的函数调用，那么我们
        // 直接返回一个模块内的内存地址，当系统调用进入这个函数时，比如
        // 通过Ret,或者jmp，那么我们检测这个地址是否跟我们模块内这个特殊
        // 地址一样，假如是的话，我们要额外执行一次ret操作。因为跳转到外部
        // 的call函数以后，等他执行完了，他需要ret到我们内部的地址上
        //t_addr = pe_loader_va2fa2(mod->pe_mod, va);
        if (vmp_hlp_get_symbol(mod->hlp, va - FAKE_IMAGE_BASE, sym_name, sizeof (sym_name), NULL))
        {
            printf("find symbol[%s]\n", sym_name);
        }

        t_addr = mod->mem.external_call;
    }
    // FIXME
    else if ((va & 0xffff) == 0x20bc)
    { 
        t_addr = mod->mem.external_call;
    }
    else if ((va >= mod->stack.esp_start) && (va <= mod->stack.esp_end))
    {
        new_addr = (uint8_t *)((uint64_t)va | mod->addr64_prefix);
    }
    else
    { 
        new_addr = (uint8_t *)((uint64_t)va | mod->addr64_prefix);
        t_addr = pe_loader_va2fa(mod->pe_mod, new_addr);
    }


    // 地址假如在PE文件内，那么我们就把这个虚拟地址转成当前文件地址
    // 假如不在，那么就是堆栈地址

    return t_addr?t_addr:new_addr;
}
uint8_t *x86_emu_access_esp(struct x86_emu_mod *mod)
{
    return ((uint8_t *)((mod)->addr64_prefix | (uint64_t) mod->esp.u.r32));
}

int x86_emu_stack_top(struct x86_emu_mod *mod)
{
    return (int)(x86_emu_access_esp(mod) - mod->stack.data);
}

uint8_t *x86_emu_eip(struct x86_emu_mod *mod)
{
    uint8_t *new_addr;

    if ((mod->eip.u.r32 & 0xffC00000) == FAKE_IMAGE_BASE)
    {
        return pe_loader_va2fa2(mod->pe_mod, mod->eip.u.r32);
    }
    else 
    {
        new_addr = (uint8_t *)(mod->addr64_prefix | (uint64_t)mod->eip.u.r32);
        if (mod->inst.is_fa)
            return new_addr;

        return new_addr ? pe_loader_va2fa(mod->pe_mod, new_addr):NULL;
    }

}

uint8_t *x86_emu_reg8_get_ptr(struct x86_emu_mod *mod, int reg_type)
{
    struct x86_emu_reg *regs = &mod->eax;

    return (reg_type < 4) ? &regs[reg_type % 4].u._r16.r8l:&regs[reg_type % 4].u._r16.r8h;
}

uint8_t *x86_emu_reg8_get_known_ptr(struct x86_emu_mod *mod, int reg_type)
{
    struct x86_emu_reg *regs = &mod->eax;

    return (reg_type < 4) ? ((uint8_t *)(&regs[reg_type % 4].known))
        :(((uint8_t *)(&regs[reg_type % 4].known)) + 1);
}

#ifdef __cplusplus
}
#endif
