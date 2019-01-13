
#ifndef __x86_emu_h__
#define __x86_emu_h__

#include <stdint.h>

#define REG_TYPE_EAX            1
#define REG_TYPE_EBX            2
#define REG_TYPE_ECX            3
#define REG_TYPE_EDX            4
#define REG_TYPE_EDI            5
#define REG_TYPE_ESI            6
#define REG_TYPE_EBP            7
#define REG_TYPE_ESP            8

typedef struct x86_emu_reg
{
    uint32_t    type;
    uint32_t    known;
    uint32_t    val;
} x86_emu_reg_t;

typedef struct x86_emu_operand
{
    enum
    {
        a_imm8,
        a_imm16,
        a_imm32,
        a_imm64,
        a_immN,
        a_reg8,
        a_reg16,
        a_reg32,
        a_reg64,
    } kind;

    union
    {
        uint8_t     v8;
        uint16_t   v16;
        uint32_t   v32;
        uint64_t   v64;
        int        vN;
        struct x86_emu_reg reg;
    } u;
} _x86_emu_operand;

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
} x86_emu_eflags_t;

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

    struct x86_emu_operand stack[1024];
} x86_emu_mod;

struct x86_emu_mod *x86_emu_create(int word_size);
int x86_emu_destroy(struct x86_emu_mod *);


int x86_emu_run(struct x86_emu_mod *mod, char *code, int len);

int x86_emu_push_reg(struct x86_emu_mod *mod, int reg, int val, int siz);
int x86_emu_push_imm(struct x86_emu_mod *mod, int val, int siz);


#endif