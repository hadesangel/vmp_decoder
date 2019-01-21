

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __x86_emu_h__
#define __x86_emu_h__

#include <stdint.h>

#define OPERAND_TYPE_REG_EAX    1    
#define OPERAND_TYPE_REG_EBX    2
#define OPERAND_TYPE_REG_ECX    3    
#define OPERAND_TYPE_REG_EDX    4    
#define OPERAND_TYPE_REG_EDI    5    
#define OPERAND_TYPE_REG_ESI    6    
#define OPERAND_TYPE_REG_EBP    7    
#define OPERAND_TYPE_REG_ESP    8    

#define OPERAND_TYPE_IMM        16

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
        (_r)->u.r32 = (_v); \
    } while (0)


typedef struct x86_emu_reg
{
    uint32_t    type;
    uint32_t    known;
    union
    {
        uint8_t     r8;
        uint16_t    r16;
        uint32_t    r32;
        uint64_t    r64;
    } u;
} x86_emu_reg_t;

#endif


typedef struct x86_emu_eflags
{
    unsigned int cf     : 1;    // carray flag
    unsigned int bit1   : 1;    // reserved
    unsigned int pf     : 1;    // parity flag  
    unsigned int bit3   : 1; 
    unsigned int af     : 1;    // auxiliary flag
    unsigned int bit5   : 1;    
    unsigned int zf     : 1;    // zero flag
    unsigned int sf     : 1;    // sign flag
    unsigned int tf     : 1;    // trap flag
    unsigned int ief    : 1;    // interrupt enable flag
    unsigned int df     : 1;    // direction flag
    unsigned int of     : 1;    // overflow flag
    unsigned int iopl   : 1;    // I/O privilege level
    unsigned int nt     : 1;    // nested task
    unsigned int bit15  : 1;
    unsigned int rf     : 1;    // resume flag
    unsigned int vm     : 1;    // virtual-8086 mode 
    unsigned int ac     : 1;    // alignment check
    unsigned int vif    : 1;    // virtual interupt flag;

    struct 
    {
        unsigned int cf     : 1;    
        unsigned int bit1   : 1;    
        unsigned int pf     : 1;    
        unsigned int bit3   : 1; 
        unsigned int af     : 1;    
        unsigned int bit5   : 1;    
        unsigned int zf     : 1;    
        unsigned int sf     : 1;    
        unsigned int tf     : 1;    
        unsigned int ief    : 1;    
        unsigned int df     : 1;    
        unsigned int of     : 1;    
        unsigned int iopl   : 1;    
        unsigned int nt     : 1;    
        unsigned int bit15  : 1;
        unsigned int rf     : 1;    
        unsigned int vm     : 1;    
        unsigned int ac     : 1;    
        unsigned int vif    : 1;    
    } known;
} x86_emu_eflags_t;

typedef enum {
    a_imm8,
    a_imm16,
    a_imm32,
    a_imm64,
    a_immN,
    a_reg8,
    a_reg16,
    a_reg32,
    a_reg64,
    a_eflags,
} x86_emu_operand_type;

typedef struct x86_emu_operand
{
    x86_emu_operand_type kind;
    
    union
    {
        uint8_t     imm8;
        uint16_t    imm16;
        uint32_t    imm32;
        uint64_t    imm64;
        int         vN;
        struct x86_emu_reg reg;
        struct x86_emu_eflags eflags;
    } u;
} x86_emu_operand_t;

typedef struct x86_emu_mod
{
    // 不要改变通用寄存器的位置，我在代码里面某些地方把他当成一个数组来处理了
    struct x86_emu_reg eax;
    struct x86_emu_reg ebx;
    struct x86_emu_reg ecx;
    struct x86_emu_reg edx;
    struct x86_emu_reg edi;
    struct x86_emu_reg esi;
    struct x86_emu_reg ebp;
    struct x86_emu_reg esp;

    x86_emu_eflags_t    eflags;

    struct 
    {
        struct x86_emu_operand  data[1024];
        int top;
        int size;
    } stack;


    struct {
        uint8_t     *start;
        int         len;
        int         oper_size;
    } inst;
} x86_emu_mod_t;

typedef int(*x86_emu_on_inst) (struct x86_emu_mod *mod, uint8_t *addr, int len);

typedef struct x86_emu_on_inst_item
{
    uint32_t            type;
    // x86指令集中，有些指令是无法根据第一个字节判断出指令类型的
    // 需要结合第2个指令，比如
    // 81 e2 28 02 1e 46        [and edx, 0x461e0228]
    // 81 f6 a2 70 21 62        [xor esi, 0x622170a2]
    // 这些指令需要提取modrm，也就是第2个字节中的reg field来做甄别。
    int                 reg;
    x86_emu_on_inst     on_inst;
} x86_emu_on_inst_item_t;


struct x86_emu_mod *x86_emu_create(int word_size);
int x86_emu_destroy(struct x86_emu_mod *mod);

int x86_emu_run(struct x86_emu_mod *mod, uint8_t *code, int len);

int x86_emu_push_reg(struct x86_emu_mod *mod, int reg_type);
int x86_emu_push_imm(struct x86_emu_mod *mod, int val);
int x86_emu_push_eflags(struct x86_emu_mod *mod);


#endif

#ifdef __cplusplus
}
#endif