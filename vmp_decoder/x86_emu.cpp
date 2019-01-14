
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include "x86_emu.h"
#include "mbytes.h"

static int x86_emu_modrm_analysis(uint8_t modrm, int *dst_type, int *src_type);
static struct x86_emu_reg *x86_emu_reg_get(struct x86_emu_mod *mod, int reg_type);
static int x86_emu_modrm_analysis2(struct x86_emu_mod *mod, uint8_t *cur, int oper_size1, int *dst_type, int *src_type, struct x86_emu_reg *imm);

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

int x86_emu_sbb (struct x86_emu_mod *mod, int reg_dst, int reg_src)
{
    return 0;
}

// 右移指令的操作数不止是寄存器，但是这个版本中，先只处理寄存器
int x86_emu_shrd (struct x86_emu_mod *mod, int reg_dst, int reg_src, int count)
{
    return 0;
}

int x86_emu_bts(struct x86_emu_mod *mod, int reg_dst, int reg_src)
{
    if (mod->inst.oper_size == 16)
    { 
    }
    return 0;
}

int x86_emu_xor(struct x86_emu_mod *mod, int dst_type, int src_type, uint32_t imm)
{
    struct x86_emu_reg *src_reg, *dst_reg;
    uint32_t v32; 
    uint16_t v16;

    if (src_type == dst_type)
    {
        src_reg = x86_emu_reg_get(mod, src_type);

        src_reg->known = 0xffffffff;
        X86_EMU_REG_SET_r32(src_reg, 0);
    }
    else if (src_type == OPERAND_TYPE_IMM)
    {
        dst_reg = x86_emu_reg_get(mod, dst_type);

        if (mod->inst.oper_size == 32)
        {
            v32 = X86_EMU_REG_GET_r32(dst_reg);
            v32 ^= imm;
            X86_EMU_REG_SET_r32(dst_reg, v32);
        }
        else if (mod->inst.oper_size == 16)
        {
            v16 = X86_EMU_REG_GET_r16(dst_reg);;
            v16 ^= (uint16_t)imm;
            X86_EMU_REG_SET_r16(dst_reg, v16);
        }
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

static inline int x86_emu_inst_init(struct x86_emu_mod *mod, uint8_t *inst, int len)
{
    mod->inst.oper_size = 32;
    mod->inst.start = inst;
    mod->inst.len = len;

    return 0;
}

int x86_emu_run(struct x86_emu_mod *mod, uint8_t *addr, int len)
{
    uint32_t i32;
    uint16_t i16;

    x86_emu_inst_init(mod, addr, len);
    int i = 1, src_type, dst_type;
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
        i = 0;
        break;
    }

    switch (addr[i])
    {
        // xor
    case 0x33:
        x86_emu_modrm_analysis(addr[i+1], &dst_type, &src_type);
        x86_emu_xor(mod, dst_type, src_type, 0);
        break;

        // xor
        // xor有多种不同类型的指令格式，本来出于美观的考虑，我应该让switch ... case
        // 里面的语句按字节大小的顺序排列，但是为了看的更清楚一些，就把相同类型的指令
        // 放在一起了.
    case 0x81:
        x86_emu_modrm_analysis(addr[i+1], &dst_type, &src_type);
        if (mod->inst.oper_size == 32)
        { 
            i32 = mbytes_read_int_little_endian_4b(addr + i + 2);
        }
        else
        {
            i32 = mbytes_read_int_little_endian_2b(addr + i + 2);
        }
        x86_emu_xor(mod, dst_type, src_type, i32);
        break;

        // push edx
    case 0x52:
        x86_emu_push_reg(mod, OPERAND_TYPE_REG_EDX);
        break;

        // push ebp
    case 0x55:
        x86_emu_push_reg(mod, OPERAND_TYPE_REG_EBP);
        break;

        // lea
    case 0x8d:
        x86_emu_modrm_analysis(addr[i+1], &dst_type, &src_type);
        break;

    // mov bp
    case 0xbd:
        i16 = mbytes_read_int_little_endian_2b(addr + 2);
        //decoder->x86_emulator.ebp = i16;
        break;

    case 0x0f:
        switch (addr[i+1])
        { 
            // shrd
        case 0xac:
            x86_emu_modrm_analysis(addr[i+2], &src_type, &dst_type);
            x86_emu_shrd(mod, dst_type, src_type, addr[i+3]);
            break;

            // bt
        case 0xba:
            // 0x0f 0xba是不定长指令，这个地方，我们应该去处理ModR/M格式的数据但是这里为了简化处理，
            // 我们直接判断这个值了，因为看起来vmp生成的格式数据就这么几个套路
            if (addr[i+2] == 0xe5)
            {
                if (addr[i + 3] > 32)
                {
                    X86_EMU_REG_SET_r32(&mod->ebp, 0);
                }
            }
            break;

            // bts
        case 0xab:
            x86_emu_modrm_analysis(addr[i+2], &src_type, &dst_type);
            x86_emu_bts(mod, dst_type, src_type);
            break;

        default:
            printf("vmp_x86_emulator() meet unknow instruct. %s:%d\r\n", __FILE__, __LINE__);
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
static int x86_emu_modrm_analysis2(struct x86_emu_mod *mod, uint8_t *cur, int oper_size1, int *dst_type, int *src_type, struct x86_emu_reg *imm)
{
    uint8_t modrm = cur[0];
    uint8_t v8;
    uint32_t v32;
    struct x86_emu_reg *reg;
    int oper_size = oper_size1 ? oper_size1 : mod->inst.oper_size;

    int mod1 = modrm >> 6;
    int rm1 = modrm & 3;
    int reg1 = (modrm >> 2) & 3;

    switch (mod1)
    {
    case 0:
        break;

        // 加立即数，不会修改寄存器中值的 known 状态
    case 1:
        *src_type = modrm_rm_tabl[reg1];
        reg = x86_emu_reg_get(mod, *src_type);
        v8 = cur[1];

        *imm = *reg;
        imm->u.r8 += v8;
        break;

    case 2:
        *src_type = modrm_rm_tabl[reg1];
        reg = x86_emu_reg_get(mod, *src_type);
        v32 = mbytes_read_int_little_endian_4b(cur + 1);

        *imm = *reg;
        imm->u.r32 += v32;
        break;

    case 3:
        *src_type = modrm_rm_tabl[reg1];
        reg = x86_emu_reg_get(mod, *src_type);
        *dst_type = modrm_rm_tabl[rm1];
        break;
    }

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

#ifdef __cplusplus
}
#endif
