

#include <stdio.h>
#include <stdlib.h>
#include "x86_emu.h"


struct x86_emu_mod *x86_emu_create(int word_size)
{
    struct x86_emu_mod *mod;

    mod = calloc(1, sizeof (mod[0]));
    if (!mod)
    {
        printf("x86_emu_create() failed when calloc(). %s:%d", __FILE__, __LINE__);
        return NULL;
    }

    mod->eax.bm.reg_type = REG_TYPE_EAX;
    mod->ebx.bm.reg_type = REG_TYPE_EBX;
    mod->ecx.bm.reg_type = REG_TYPE_ECX;
    mod->edx.bm.reg_type = REG_TYPE_EDX;
    mod->edi.bm.reg_type = REG_TYPE_EDI;
    mod->esi.bm.reg_type = REG_TYPE_ESI;
    mod->ebp.bm.reg_type = REG_TYPE_EBP;
    mod->esp.bm.reg_type = REG_TYPE_ESP;

    return mod;
}
int x86_emu_destroy(struct x86_emu_mod *);

int x86_emu_push_reg(struct x86_emu_mod *mod, int reg_type, int siz)
{
    x86_emu_reg_t *regs = &mod->eax;
    int i, byte;

    if ((siz != 8) && (size != 16) && (size != 32))
    {
        printf("x86_emu_push_reg() failed with invalid param(size=%d). %s:%d", siz, __FILE__, __LINE__);
        return -1;
    }

    for (i = 0; i < 8; i++)
    {
        if (regs[i].bm.reg_type == reg)
        {
        }
    }

    return 0;
}

int x86_emu_push_imm(int val, int siz)
{
    return 0;
}

int x86_emu_run(struct x86_emu_mod *mod, unsigned char *code, int len);
{
    uint32_t i32;
    uint16_t i16;

    int b32 = 1;
    int i = 1;

    // Instruction prefixes are divided into four groups, each with a set of allowable prefix codex. 
    // For each instruction, it is only useful to include up to one prefix code from each of the four
    // groups (Groups 1, 2, 3, 4).
    switch (addr[0])
    {
    case 0x66:
        b32 = 0;
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
        i = 0;
        break;
    }

    switch (addr[i])
    {
    case 0x52:
        x86_emu_push_reg();
        vmp_x86_push_i32(decoder, decoder->x86_emulator.edx, NULL, 0);
        break;

        // push ebp
    case 0x55:
        vmp_x86_push_i32(decoder, decoder->x86_emulator.ebp, NULL, 0);
        break;

    // mov bp
    case 0xbd:
        i16 = mbytes_read_int_little_endian_2b(addr + 2);
        decoder->x86_emulator.ebp = i16;
        break;

    case 0x0f:
        switch (addr[i+1])
        { 
            // bt
        case 0xba:
            // 0x0f 0xba是不定长指令，这个地方，我们应该去处理ModR/M格式的数据但是这里为了简化处理，
            // 我们直接判断这个值了，因为看起来vmp生成的格式数据就这么几个套路
            if (addr[i+2] == 0xe5)
            {
                if (addr[i + 3] > 32)
                {
                    decoder->x86_emulator.ebp = 0;
                }
            }
            break;

        default:
            printf("vmp_x86_emulator() meet unknow instruct. %s:%d\r\n", __FILE__, __LINE__);
            break;
        }
        break;

        // push i32
    case 0x68:
        vmp_x86_push_i32(decoder, 0, addr, 4);
        break;

        // pushfd
    case 0x9c:
        vmp_x86_push_i32(decoder, decoder->x86_emulator.eflags, NULL, 0);
        break;
    }
    return 0;
}
