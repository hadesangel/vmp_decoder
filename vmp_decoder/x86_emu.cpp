
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "x86_emu.h"
#include "mbytes.h"

#define time2s(_t)                  ""
#define print_err                   printf

static struct x86_emu_reg *x86_emu_reg_get(struct x86_emu_mod *mod, int reg_type);
static int x86_emu_modrm_analysis2(struct x86_emu_mod *mod, uint8_t *cur, int oper_size1, int *dst_type, int *src_type, struct x86_emu_reg *imm);
static int x86_emu_add_modify_status(struct x86_emu_mod *mod, uint32_t dst, uint32_t src);

static int x86_emu_cf_set(struct x86_emu_mod *mod, uint32_t v);
static int x86_emu_cf_get(struct x86_emu_mod *mod);
static int x86_emu_of_set(struct x86_emu_mod *mod, int v);
static int x86_emu_sf_set(struct x86_emu_mod *mod, int v);
static int x86_emu_zf_set(struct x86_emu_mod *mod, int v);
static int x86_emu_zf_get(struct x86_emu_mod *mod);
static int x86_emu_pf_set(struct x86_emu_mod *mod, int v);
static int x86_emu__push_reg(struct x86_emu_mod *mod, int oper_siz1, struct x86_emu_reg *reg);
static int x86_emu__push_imm8(struct x86_emu_mod *mod, uint8_t imm8);
static int x86_emu__push_imm16(struct x86_emu_mod *mod, uint16_t imm16);
static int x86_emu__push_imm32(struct x86_emu_mod *mod, uint32_t imm32);
int x86_emu_pushfd(struct x86_emu_mod *mod, uint8_t *code, int len);

int x86_emu_add(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_lea(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_mov(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_xor(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_bt(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_bts(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_btc(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_dec(struct x86_emu_mod *mod, uint8_t *code, int len);

int x86_emu_rol(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_ror(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_rcl(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_rcr(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_shr(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_neg(struct x86_emu_mod *mod, uint8_t *code, int len);

// todo:
int x86_emu_bswap(struct x86_emu_mod *mod, uint8_t *code, int len);
int x86_emu_clc(struct x86_emu_mod *mod, uint8_t *code, int len);

static uint32_t x86_emu_reg_val_get(int oper_siz, struct x86_emu_reg *reg);

#define X86_EMU_REG_IS_KNOWN(_op_siz, _reg)                 (((_op_siz == 32) && ((_reg)->known == 0xffffffff)) || ((_op_siz == 16) && ((_reg)->known == 0xffff)))
#define X86_EMU_REG_H8_IS_KNOWN(_reg)                       ((_reg)->known & 0x0000ff00)
#define X86_EMU_REG_BIT_IS_KNOWN(_op_siz, _reg, _bit_pos)   ((_reg)->known & (1 << (_bit_pos % _op_siz)))
#define X86_EMU_EFLAGS_BIT_IS_KNOWN(_bit)                   ((_bit) >= 0)

#define MODRM_GET_MOD(_c)   ((_c) >> 6)
#define MODRM_GET_RM(_c)    ((_c) & 7)
#define MODRM_GET_REG(_c)   (((_c) >> 3) & 7)
#define SIB_GET_SCALE(_c)   ((_c) >> 6)
#define SIB_GET_INDEX(_c)    ((_c) & 7)
#define SIB_GET_BASE(_c)   (((_c) >> 3) & 7)

#define X86_EMU_REG_AL(_mod)            (_mod)->eax.u._r16.r8l
#define X86_EMU_REG_AH(_mod)            (_mod)->eax.u._r16.r8h
#define X86_EMU_REG_BL(_mod)            (_mod)->ebx.u._r16.r8l
#define X86_EMU_REG_BH(_mod)            (_mod)->ebx.u._r16.r8h
#define X86_EMU_REG_CL(_mod)            (_mod)->ecx.u._r16.r8l
#define X86_EMU_REG_CH(_mod)            (_mod)->ecx.u._r16.r8h
#define X86_EMU_REG_DL(_mod)            (_mod)->edx.u._r16.r8l
#define X86_EMU_REG_DH(_mod)            (_mod)->edx.u._r16.r8h

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
            x86_emu_add_modify_status(mod, _dst_reg->u.r32, _sign ? (~(_src_reg->u.r32 + _cf) + 1):_src_reg->u.r32); \
        } \
        else if (mod->inst.oper_size == 16) \
        { \
            x86_emu_add_modify_status(mod, dst_reg->u.r16, _sign ? (~(_src_reg->u.r16 + _cf) + 1):_src_reg->u.r16); \
        } \
    } while (0)

#define x86_emu_add_dynam_rr(_dst_reg, oper, _src_reg, _cf) \
    do{ \
        if (mod->inst.oper_size == 32) \
        { \
            _dst_reg->u.r32 oper (_src_reg->u.r32 + _cf); \
        } \
        else if (mod->inst.oper_size == 16) \
        { \
            _dst_reg->u.r16 oper (_src_reg->u.r16 + _cf); \
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

    mod->stack.top = -1;
    mod->stack.size = counts_of_array (mod->stack.data);

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
        x86_emu_push_reg(mod, OPERAND_TYPE_REG_EAX);
        break;

    case 0x51:
        x86_emu_push_reg(mod, OPERAND_TYPE_REG_ECX);
        break;

    case 0x52:
        x86_emu_push_reg(mod, OPERAND_TYPE_REG_EDX);
        break;

        // ebx
    case 0x53:
        x86_emu_push_reg(mod, OPERAND_TYPE_REG_EBX);
        break;

        // push ebp
    case 0x55:
        x86_emu_push_reg(mod, OPERAND_TYPE_REG_EBP);
        break;

    case 0x56:
        x86_emu_push_reg(mod, OPERAND_TYPE_REG_ESI);
        break;

        // push edi
    case 0x57:
        x86_emu_push_reg(mod, OPERAND_TYPE_REG_EDI);
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

    return 0;
}

int x86_emu_push_imm(struct x86_emu_mod *mod, int val)
{
    return 0;
}

int x86_emu_pushfd (struct x86_emu_mod *mod, uint8_t *code, int len)
{
    x86_emu_operand_t *oper;

    if ((mod->stack.top + 1) >= mod->stack.size)
    {
        printf("x86_emu_pushfd() failed when stack overflow()");
        return -1;
    }

    oper = &mod->stack.data[mod->stack.top+1];
    oper->kind = a_eflags;
    oper->u.eflags = mod->eflags;

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
    }
    return 0;
}

int x86_emu_rol(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    return 0;
}

int x86_emu_ror(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    return 0;
}

int x86_emu_rcl(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    return 0;
}

int x86_emu_rcr(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    return 0;
}

int x86_emu_shr(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    return 0;
}

int x86_emu_neg(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *dst_reg;

    switch (code[0])
    {
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
    }
    return 0;
}

int x86_emu_shl(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int cts;
    x86_emu_reg_t *dst_reg, *src_reg;

    switch (code[0])
    {
    case 0xc1:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        cts = code[2] & 0x1f;
        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, dst_reg))
        {
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
        }
        break;

    case 0xd2:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));

        if (MODRM_GET_REG(code[1]) < 4)
        { 
            x86_emu_cf_set(mod, dst_reg->u._r16.r8l & (1 << (8 - X86_EMU_REG_CL(mod))));
            dst_reg->u._r16.r8l <<= X86_EMU_REG_CL(mod);
        }
        else
        { 
            x86_emu_cf_set(mod, dst_reg->u._r16.r8h & (1 << (8 - X86_EMU_REG_CL(mod))));
            dst_reg->u._r16.r8h <<= X86_EMU_REG_CL(mod);
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
    int dst_type, src_type;
    struct x86_emu_reg src_imm = {0}, *dst_reg;
    uint32_t src_val, dst_val;

    x86_emu_modrm_analysis2(mod, code, 0, &dst_type, &src_type, &src_imm);

    dst_reg = x86_emu_reg_get (mod, MODRM_GET_RM(code[1]));
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
    struct x86_emu_reg *dst_reg = NULL, *src_reg, src_imm = {0};

    switch (code[0])
    {
    case 0xb9:
    case 0xba:
        dst_reg = x86_emu_reg_get (mod, code[0] - 0xb8);
        x86_emu_dynam_imm_set (dst_reg, code + 1);
        break;

    case 0xbd:
        dst_reg = x86_emu_reg_get(mod, OPERAND_TYPE_REG_EBP);
        x86_emu_dynam_imm_set(dst_reg, code + 1);
        break;

    case 0x8b:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[0]));
        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, src_reg))
        {
            x86_emu_dynam_oper(dst_reg, =, src_reg);
        }
        break;

    default:
        return -1;
    }

    return 0;
}

int x86_emu_add(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int dst_type = 0, src_type = 0;
    x86_emu_reg_t *dst_reg, *src_reg;

    switch (code[0])
    {
    case 0x03:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));

        if (X86_EMU_REG_IS_KNOWN (mod->inst.oper_size, dst_reg)
            && X86_EMU_REG_IS_KNOWN (mod->inst.oper_size, src_reg))
        { 
            x86_emu_add_dynam_modify_status_rr(dst_reg, src_reg, 0, 0);
        }

        x86_emu_dynam_oper(dst_reg, +=, src_reg);
        break;

    case 0x80:
        mod->inst.oper_size = 8;
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, dst_reg))
        {
            x86_emu_add_modify_status(mod, dst_reg->u._r16.r8h, code[2]);
        }
        dst_reg->u._r16.r8h += code[2];
        break;

    default:
        return -1;
    }
    return 0;
}

int x86_emu_and(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg src_imm = {0}, *dst_reg;

    switch (code[0])
    {
    case 0x81:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        x86_emu_dynam_oper(dst_reg, &=, &src_imm);
        x86_emu_cf_set(mod, 0);
        x86_emu_of_set(mod, 0);

        if (X86_EMU_REG_IS_KNOWN (mod->inst.oper_size, dst_reg))
        { 
            x86_emu_sf_set(mod, dst_reg->u.r32 & (1 < (mod->inst.oper_size - 1)));
            x86_emu_pf_set(mod, count_1bit((mod->inst.oper_size == 32) ? dst_reg->u.r32:dst_reg->u.r16));
        }
        break;

    default:
        return -1;
    }

    return 0;
}

int x86_emu_or(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    x86_emu_reg_t *dst_reg, *src_reg;

    switch (code[0])
    {
    case 0x0a:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, dst_reg)
            && X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, src_reg))
        {
            x86_emu_dynam_oper(dst_reg, |=, src_reg);
        }
        break;
    }
    return 0;
}


// 本来计算这个状态会带入cf的标志的，后来发现没有必要，而且在计算
// 减法时状态不对，直接让API在上层计算了带进来
static int x86_emu_add_modify_status(struct x86_emu_mod *mod, uint32_t dst, uint32_t src)
{
    int oper_siz = mod->inst.oper_size;

    int sign_src = src & (1 << (oper_siz - 1)), sign_dst = dst & (1 << (oper_siz - 1)), sign_s;

    uint32_t s = 0;

    uint32_t c = 0;

    switch (oper_siz / 8)
    {
    case 1:
        s = (uint8_t)((uint8_t)dst + (uint8_t)src);
        break;

    case 2:
        s = (uint16_t)((uint16_t)dst + (uint16_t)src );
        break;

    case 4:
        s = dst + src;
        break;
    }
    c = (s < dst);
    x86_emu_cf_set(mod, !!c);

    sign_s = (1 << (oper_siz - 1));

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
    int ret;
    struct x86_emu_reg *dst_reg, *src_reg, src_imm = {0};

    switch(code[0])
    {
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

    default:
        return -1;
    }
    return 0;
}


int x86_emu_sub(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *dst_reg, *src_reg;

    switch (code[0])
    {
    case 0x2b:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[0]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[0]));
        x86_emu_add_dynam_rr(dst_reg, -=, src_reg, 0);
        break;
    }
    return 0;
}

int x86_emu_cmp(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int32_t v;
    x86_emu_reg_t *dst_reg, *src_reg, src_imm = {0};

    switch (code[0])
    {
    case 0x3b:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[2]));
        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, dst_reg)
            && X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, src_reg))
        {
            if (mod->inst.oper_size == 32)
            {
                x86_emu_add_modify_status(mod, dst_reg->u.r32, - (int32_t)src_reg->u.r32);
            }
            else if (mod->inst.oper_size == 16)
            {
                x86_emu_add_modify_status(mod, dst_reg->u.r16, - (int16_t)src_reg->u.r16);
            }
        }
        break;

    case 0x80:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        if (X86_EMU_REG_H8_IS_KNOWN(dst_reg))
        {
            mod->inst.oper_size = 8;
            x86_emu_add_modify_status(mod, dst_reg->u._r16.r8h, - code[1]);
        }
        break;

    case 0x81:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, dst_reg))
        {
            if (mod->inst.oper_size == 32)
            {
                v = mbytes_read_int_little_endian_4b(code + 2);
                x86_emu_add_modify_status(mod, dst_reg->u.r32, - v);
            }
            else if (mod->inst.oper_size == 16)
            {
                v = mbytes_read_int_little_endian_2b(code + 2);
                x86_emu_add_modify_status(mod, dst_reg->u.r16, - v);
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
    int dst_type = 0;
    x86_emu_reg_t *dst_reg, *src_reg;
    switch (code[0])
    { 
    case 0x85:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));

        x86_emu_test_modify_status(mod, 
            x86_emu_reg_val_get(mod->inst.oper_size, dst_reg),
            x86_emu_reg_val_get(mod->inst.oper_size, src_reg));
        break;

    case 0xa9:
        dst_type = OPERAND_TYPE_REG_EAX;
    case 0xf7:
        if (!dst_type) dst_type = MODRM_GET_RM(code[1]);
        dst_reg = x86_emu_reg_get(mod, dst_type);
        x86_emu_test_modify_status(mod, 
            x86_emu_reg_val_get(mod->inst.oper_size, dst_reg),
            (mod->inst.oper_size == 32) ? mbytes_read_int_little_endian_4b(code + 2)
            : mbytes_read_int_little_endian_2b(code + 2));
        break;

    default:
        return -1;
    }
    return 0;
}

int x86_emu_not(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    x86_emu_reg_t *dst_reg;
    switch (code[0])
    {
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
    return 0;
}

int x86_emu_imul(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    return 0;
}

int x86_emu_div(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    return 0;
}

int x86_emu_idiv(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    return 0;
}

int x86_emu_movzx(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    x86_emu_reg_t *src_reg, *dst_reg, src_imm = {0};

    switch (code[0])
    {
    case 0xb7:
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        src_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (X86_EMU_REG_IS_KNOWN(16, src_reg))
        {
            dst_reg->u.r32 = src_reg->u.r16;
            dst_reg->known = 0xffffffff;
        }
        break;

    default:
        return -1;
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
        src_reg = x86_emu_reg_get(mod, MODRM_GET_REG(code[1]));
        dst_reg = x86_emu_reg_get(mod, MODRM_GET_RM(code[1]));
        if (X86_EMU_EFLAGS_BIT_IS_KNOWN ((cf = x86_emu_cf_get(mod)))
            && X86_EMU_EFLAGS_BIT_IS_KNOWN((zf = x86_emu_zf_get(mod)))
            && X86_EMU_REG_IS_KNOWN(mod->inst.oper_size, src_reg))
        {
            x86_emu_dynam_oper(dst_reg, =, src_reg);
        }
    }
    return 0;
}

#define bswap(_a, _b) \
    do { \
        uint8_t t = _a; \
        _a = _b; \
       _b = t; \
    } while(0)

int x86_emu_bswap(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    x86_emu_reg_t *reg;
    uint8_t *s;

    switch (code[0])
    {
    case 0xca:
        reg = x86_emu_reg_get(mod, OPERAND_TYPE_REG_EDX);
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

static int x86_emu_cmc(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    int cf;
    if (X86_EMU_EFLAGS_BIT_IS_KNOWN((cf = x86_emu_cf_get(mod))))
    {
        x86_emu_cf_set(mod, !cf);
    }

    return 0;
}

static int x86_emu_dec(struct x86_emu_mod *mod, uint8_t *code, int len)
{
    struct x86_emu_reg *reg;
    switch (code[0])
    {
    case 0x4e:
        reg = x86_emu_reg_get(mod, code[0] - 0x48);
        x86_emu_dynam_oper_imm(reg, -=, 1);
        x86_emu_add_modify_status(mod, (mod->inst.oper_size == 32) ? reg->u.r32:reg->u.r16, -1);
        break;

    default:
        return -1;
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

    { 0x13, -1, x86_emu_adc },
    { 0x1b, -1, x86_emu_sbb },
    { 0x2b, -1, x86_emu_sub },
    { 0x0a, -1, x86_emu_or },
    { 0x03, -1, x86_emu_add },
    { 0x33, -1, x86_emu_xor },
    { 0x3b, -1, x86_emu_cmp },
    { 0x4e, -1, x86_emu_dec },
    { 0x50, -1, x86_emu_push },
    { 0x51, -1, x86_emu_push },
    { 0x52, -1, x86_emu_push },
    { 0x53, -1, x86_emu_push },
    { 0x55, -1, x86_emu_push },
    { 0x56, -1, x86_emu_push },
    { 0x57, -1, x86_emu_push },
    { 0x68, -1, x86_emu_push },
    { 0x80, 0, x86_emu_add },
    { 0x80, 1, x86_emu_or },
    { 0x80, 2, x86_emu_adc },
    { 0x80, 3, x86_emu_sbb },
    { 0x80, 4, x86_emu_and },
    { 0x80, 5, x86_emu_sub },
    { 0x80, 6, x86_emu_xor },
    { 0x80, 7, x86_emu_cmp },
    { 0x81, 0, x86_emu_add },
    { 0x81, 1, x86_emu_or },
    { 0x81, 2, x86_emu_adc },
    { 0x81, 3, x86_emu_sbb },
    { 0x81, 4, x86_emu_and },
    { 0x81, 5, x86_emu_sub },
    { 0x81, 6, x86_emu_xor },
    { 0x81, 7, x86_emu_cmp },
    { 0x85, -1, x86_emu_test },
    { 0x8b, -1, x86_emu_mov },
    { 0x8d, -1, x86_emu_lea },
    { 0xba, -1, x86_emu_mov },
    { 0xbd, -1, x86_emu_mov },
    { 0x9c, -1, x86_emu_pushfd },
    { 0xa9, -1, x86_emu_test },
    { 0xb9, -1, x86_emu_mov },
    { 0xc1, 0, x86_emu_rol },
    { 0xc1, 1, x86_emu_ror },
    { 0xc1, 2, x86_emu_rcl },
    { 0xc1, 3, x86_emu_rcr },
    { 0xc1, 4, x86_emu_shl },
    { 0xc1, 5, x86_emu_shr },
    { 0xc1, 6, x86_emu_shl },
    { 0xd2, 4, x86_emu_shl },
    { 0xd3, 7, x86_emu_sar },
    { 0xf5, 0, x86_emu_cmc },
    { 0xf7, 0, x86_emu_test },
    { 0xf7, 1, x86_emu_test },
    { 0xf7, 2, x86_emu_not },
    { 0xf7, 3, x86_emu_neg },
    { 0xf7, 4, x86_emu_mul },
    { 0xf7, 5, x86_emu_imul },
    { 0xf7, 6, x86_emu_div },
    { 0xf7, 7, x86_emu_idiv },
    { 0xf8, -1, x86_emu_clc },
    { 0, -1, NULL},
};

struct x86_emu_on_inst_item x86_emu_inst_tab2[] =
{
    { 0x47, -1, x86_emu_cmovnbe },
    { 0xab, -1, x86_emu_bts },
    { 0xac, -1, x86_emu_shrd },
    { 0xb7, -1, x86_emu_movzx },
    { 0xba, -1, x86_emu_bt },
    { 0xbb, -1, x86_emu_btc },
    { 0xca, -1, x86_emu_bswap },
    { 0, -1, NULL},
};

int x86_emu_dump (struct x86_emu_mod *mod)
{
    printf("EAX[%08x:%08x], EBX[%08x:%08x], ECX[%08x:%08x], EDX[%08x:%08x], "
           "EDI[%08x:%08x], ESI[%08x:%08x], EBP[%08x:%08x], ESP[%08x:%08x]\n",
           mod->eax.known, mod->eax.u.r32, mod->ebx.known, mod->ebx.u.r32,
           mod->ecx.known, mod->ecx.u.r32, mod->edx.known, mod->edx.u.r32,
           mod->edi.known, mod->edi.u.r32, mod->esi.known, mod->esi.u.r32,
           mod->ebp.known, mod->ebp.u.r32, mod->esp.known, mod->esp.u.r32);

    return 0;
}


int x86_emu_run(struct x86_emu_mod *mod, uint8_t *addr, int len)
{
    int code_i = 1, ret = 0;
    struct x86_emu_on_inst_item *array = x86_emu_inst_tab;

    x86_emu_inst_init(mod, addr, len);

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

    if (addr[code_i] == 0x0f)
    {
        code_i ++;
        array = x86_emu_inst_tab2;
    }

    for (; array->type; array++)
    {
        if (array->type != addr[code_i])
            continue;

        if ((array->reg != -1))
        {
            if (MODRM_GET_REG(addr[code_i + 1]) == array->reg)
            {
                ret = array->on_inst(mod, addr + code_i, len - code_i);
            }
        }
        else
        {
            ret = array->on_inst(mod, addr + code_i, len - code_i);
        }

        break;
    }

    if (!array->type || (ret == -1))
    {
        print_err ("[%s] err: meet un-support instruct. %s:%d\r\n", time2s (0), __FILE__, __LINE__);
        return -1;
    }

    x86_emu_dump (mod);

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
    x86_emu_reg_t *reg, imm = {0}, *base_reg, *index_reg = NULL;
    int oper_size = oper_size1 ? oper_size1 : mod->inst.oper_size, src_type = 0, dst_type = 0;

    int mod1 = MODRM_GET_MOD(modrm);
    int rm1 = MODRM_GET_RM(modrm);
    int reg1 = MODRM_GET_REG(modrm);
    int scale = 0, index = 0, base = 0;

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
        imm.u._r16.r8l += v8;
        break;

    case 2:
        if (src_type == OPERAND_TYPE_REG_ESP)
        { // follow SIB
            scale = SIB_GET_SCALE(cur[1]);
            index = SIB_GET_INDEX(cur[1]);
            base = SIB_GET_BASE(cur[1]);

            v32 = mbytes_read_int_little_endian_4b(cur + 2);

            base_reg = x86_emu_reg_get(mod, base);
            if (index != 4)
            {
                index_reg = x86_emu_reg_get(mod, index);
            }

            imm.known = base_reg->known & (index_reg?index_reg->known:UINT_MAX);
            imm.u.r32 = base_reg->u.r32 + (index_reg?index_reg->u.r32:0)*(index^scale) + v32;
        }
        else
        {
            v32 = mbytes_read_int_little_endian_4b(cur + 1);
            imm.u.r32 += v32;
        }
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

static int x86_emu_cf_set(struct x86_emu_mod *mod, uint32_t v)
{
    mod->eflags.cf = !!v;
    mod->eflags.known.cf = 1;
    return 0;
}

static int x86_emu_cf_get(struct x86_emu_mod *mod)
{
    return (mod->eflags.known.cf ? mod->eflags.cf : -1);
}

static int x86_emu_pf_set(struct x86_emu_mod *mod, int v)
{
    mod->eflags.pf = !!v;
    mod->eflags.known.pf = 1;
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
    mod->eflags.zf = !!v;
    mod->eflags.known.zf = 1;
    return 0;
}

static int x86_emu_zf_get(struct x86_emu_mod *mod)
{
    return mod->eflags.known.zf ? mod->eflags.zf:-1;
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
        return reg->u._r16.r8l;

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

static int x86_emu__push_imm16(struct x86_emu_mod *mod, uint16_t imm16)
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

static int x86_emu__push_imm32(struct x86_emu_mod *mod, uint32_t imm32)
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
