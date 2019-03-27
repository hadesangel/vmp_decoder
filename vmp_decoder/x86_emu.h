

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __x86_emu_h__
#define __x86_emu_h__

#include <stdint.h>
#include "pe_loader.h"
#include "vmp_hlp.h"

#define OPERAND_TYPE_REG_EAX    0
#define OPERAND_TYPE_REG_ECX    1
#define OPERAND_TYPE_REG_EDX    2
#define OPERAND_TYPE_REG_EBX    3
#define OPERAND_TYPE_REG_ESP    4
#define OPERAND_TYPE_REG_EBP    5
#define OPERAND_TYPE_REG_ESI    6
#define OPERAND_TYPE_REG_EDI    7

#define OPERAND_TYPE_REG_EIP    0x0f
#define OPERAND_TYPE_IMM        0x10

#define MODRM_GET_MOD(_c)   ((_c) >> 6)
#define MODRM_GET_RM(_c)    ((_c) & 7)
#define MODRM_GET_REG(_c)   (((_c) >> 3) & 7)

#if 0

#define X86_EMU_REG_GET_r8(_r)          ((uint8_t)((_r)->val[0]))
#define X86_EMU_REG_GET_r16(_r)         *((uint16_t *)((_r)->val))
#define X86_EMU_REG_GET_r32(_r)         *((uint32_t *)((_r)->val))

#define X86_EMU_REG_SET_r8(_r, _v)      ((_r)->val[0] = (v))
#define X86_EMU_REG_SET_r16(_r, _v)     (*((uint16_t *)((_r)->val)) = (v))
#define X86_EMU_REG_SET_r32(_r, _v)     (*((uint32_t *)((_r)->val)) = (v))

typedef struct x86_emu_reg
{
    uint32_t    type;
    uint32_t    known;
    uint8_t     val[4];
} x86_emu_reg_t;

#else

#define X86_EMU_REG_GET_r8(_r)          ((_r)->u.r8)
#define X86_EMU_REG_GET_r16(_r)         ((_r)->u.r16)
#define X86_EMU_REG_GET_r32(_r)         ((_r)->u.r32)

#define X86_EMU_REG_SET_r8(_r, _v)  \
    do { \
        (_r)->known |= 0xff; \
        (_r)->u.r8 = (_v); \
    } while (0)
#define X86_EMU_REG_SET_r16(_r, _v)  \
    do { \
        (_r)->known |= 0xffff; \
        (_r)->u.r16 = (_v); \
    } while (0)
#define X86_EMU_REG_SET_r32(_r, _v)   \
    do { \
        (_r)->known |= 0xffffffff; \
        (_r)->u.r32 = (uint32_t)(_v); \
    } while (0)


typedef struct x86_emu_reg
{
    uint32_t    type;
    // 本来这里应该是64位的，但是64位很多地方我都没想清楚，所以先继续使用32位了
    uint32_t    known;
    union
    {
        struct {
            uint8_t r8l;
            uint8_t r8h;
        } _r16;
        uint16_t    r16;
        uint32_t    r32;
        uint64_t    r64;
    } u;
} x86_emu_reg_t;

#endif

// XE == x86 emulator
#define XE_EFLAGS_CF         (1 << 0)    // carray flag
#define XE_EFLAGS_B1         (1 << 1)    // reserved
#define XE_EFLAGS_PF         (1 << 2)    // parity flag
#define XE_EFLAGS_B3         (1 << 3)
#define XE_EFLAGS_AF         (1 << 4)    // auxiliary flag
#define XE_EFLAGS_B5         (1 << 5)
#define XE_EFLAGS_ZF         (1 << 6)    // zero flag
#define XE_EFLAGS_SF         (1 << 7)    // sign flag
#define XE_EFLAGS_TF         (1 << 8)    // trap flag
#define XE_EFLAGS_IEF        (1 << 9)    // interrupt enable flag
#define XE_EFLAGS_DF         (1 << 10)   // direction flag
#define XE_EFLAGS_OF         (1 << 11)   // overflow flag
#define XE_EFLAGS_IOPL       (1 << 12)   // I/O privilege level
#define XE_EFLAGS_NT         (1 << 13)   // nested task
#define XE_EFLAGS_B15        (1 << 14)
#define XE_EFLAGS_RF         (1 << 15)   // resume flag
#define XE_EFLAGS_VM         (1 << 16)   // virtual-8086 mode
#define XE_EFLAGS_AC         (1 << 17)   // alignment check
#define XE_EFLAGS_VIF        (1 << 18)   // virtual interupt flag;

#define XE_EFLAGS_SET(_eflags, flag, v)  do { \
        if (v) \
        { \
            _eflags.eflags |= flag; \
        } \
        else \
        { \
            _eflags.eflags &= ~flag; \
        } \
        _eflags.known |= flag; \
    } while (0)

typedef struct x86_emu_eflags
{
    uint32_t eflags;
    uint32_t known;
} x86_emu_eflags_t;

typedef enum {
    a_imm8,
    a_imm16,
    a_imm32,
    a_imm64,
    a_immN,
    a_mem,
    a_reg8,
    a_reg16,
    a_reg32,
    a_reg64,
    a_eflags,
} x86_emu_operand_type;

typedef struct x86_emu_mem
{
    uint32_t    known;
    uint32_t    addr32;
} _x86_emu_mem;

typedef struct x86_emu_operand
{
    x86_emu_operand_type kind;

    union
    {
        uint8_t     imm8;
        uint16_t    imm16;
        uint32_t    imm32;
        uint64_t    imm64;
        struct x86_emu_mem mem;
        int         vN;
        struct x86_emu_reg reg;
        struct x86_emu_eflags eflags;
    } u;
} x86_emu_operand_t;

#define X86_JMP         1
#define X86_COND_JMP    2

typedef struct x86_emu_flow_analysis
{
    // 1: jmp
    // 2: condition jmp 
    int jmp_type;
    int cond;
    uint8_t *true_addr;
    uint8_t *false_addr;
} x86_emu_flow_analysis_t;


typedef struct x86_emu_mod
{
    // 不要改变通用寄存器的位置，我在代码里面某些地方把他当成一个数组来处理了
    struct x86_emu_reg eax;
    struct x86_emu_reg ecx;
    struct x86_emu_reg edx;
    struct x86_emu_reg ebx;
    struct x86_emu_reg esp;
    struct x86_emu_reg ebp;
    struct x86_emu_reg esi;
    struct x86_emu_reg edi;


    struct x86_emu_reg eip;

    x86_emu_eflags_t eflags;

    // 判断机器的字长，32位系统就是32，64位就是64
    int                 word_size;

    struct
    {
        uint8_t *known;
        uint8_t *data;
        int top;
        int size;

        uint32_t    esp_start;
        uint32_t    esp_end;
    } stack;

    struct {
        uint8_t     *start;
        int         len;
        int         oper_size;
        int         rep;
        int         is_fa;
        int         count;
        uint32_t    access_addr;
        uint32_t    access_addr2;
    } inst;

    struct {
        uint8_t         external_call[4];
    } mem;

    struct pe_loader *pe_mod;
    struct vmp_hlp *hlp;

    uint64_t        addr64_prefix;
    x86_emu_flow_analysis_t analys;
} x86_emu_mod_t;

typedef int(*x86_emu_on_inst) (struct x86_emu_mod *mod, uint8_t *addr, int len);

typedef struct x86_emu_on_inst_item
{
    uint8_t             opcode[3];
    // x86指令集中，有些指令是无法根据第一个字节判断出指令类型的
    // 需要结合第2个指令，比如
    // 81 e2 28 02 1e 46        [and edx, 0x461e0228]
    // 81 f6 a2 70 21 62        [xor esi, 0x622170a2]
    // 这些指令需要提取modrm，也就是第2个字节中的reg field来做甄别。
    int8_t              reg;
    x86_emu_on_inst     on_inst;
} x86_emu_on_inst_item_t;

#define XE_DWORD_P_LOW(v32)             (v32 & 0x000000ff)
#define XE_DWORD_P_HIG(v32)             (v32 & 0x0000ff00)
#define XE_DWORD_B1(v32)                (v32 & 0x000000ff)
#define XE_DWORD_B2(v32)                (v32 & 0x0000ff00)
#define XE_DWORD_B3(v32)                (v32 & 0x00ff0000)
#define XE_DWORD_B4(v32)                (v32 & 0xff000000)

#define XE_DWORD_W1(v32)                (v32 & 0x0000ffff)
#define XE_DWORD_W2(v32)                (v32 & 0xffff0000)

struct x86_emu_create_param
{
    int word_size;
    struct pe_loader *pe_mod;
    struct vmp_hlp *hlp;
};

struct x86_emu_mod *x86_emu_create(struct x86_emu_create_param *param);
int x86_emu_destroy(struct x86_emu_mod *mod);
/*
@return     -1           failure
            0           sucess
            1           succes, and update eip
*/
#define X86_EMU_UPDATE_EIP      1
int x86_emu_run(struct x86_emu_mod *mod, uint8_t *code, int len, x86_emu_flow_analysis_t **analy);
int x86_emu_stack_is_empty(struct x86_emu_mod *mod);

uint8_t *x86_emu_eip(struct x86_emu_mod *mod);

#endif

#ifdef __cplusplus
}
#endif
