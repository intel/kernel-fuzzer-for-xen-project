/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <glib.h>

#define XC_WANT_COMPAT_MAP_FOREIGN_API 1
#include <xenctrl.h>

xc_interface *xc;
uint32_t domainid;

typedef struct CPUSegment CPUSegment;
typedef struct CPUState CPUState;

struct CPUSegment {
    uint32_t selector;
    uint32_t limit;
    uint32_t flags;
    uint32_t pad;
    uint64_t base;
};

struct CPUState {
    uint32_t version;
    uint32_t size;
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip, rflags;
    CPUSegment cs, ds, es, fs, gs, ss;
    CPUSegment ldt, tr, gdt, idt;
    uint64_t cr[5];
    uint64_t kernel_gs_base;
    uint64_t efer, xcr0;
    uint64_t star, cstar, lstar;
    uint64_t sysenter_eip, sysenter_cs, sysenter_esp;
    uint64_t dr6, dr7;
};

enum regs {
    RAX, RBX, RCX, RDX, RSI, RDI, RSP, RBP,
    R8, R9, R10, R11, R12, R13, R14, R15,
    RIP, EFLAGS,
    CS, DS, ES, FS, GS, SS,
    LDTR, TR, GDTR_BASE, GDTR_LIMIT, IDTR_BASE, IDTR_LIMIT,
    CR0, CR2, CR3, CR4,
    IA32_KERNEL_GS_BASE,
    IA32_EFER, XCR0,
    IA32_STAR, IA32_CSTAR, IA32_LSTAR,
    IA32_SYSENTER_EIP, IA32_SYSENTER_CS, IA32_SYSENTER_ESP,
    DR6, DR7,
    __MAX_REG
};

static const char* reg_names[] = {
    [RAX] = "rax", [RBX] = "rbx", [RCX] = "rcx", [RDX] = "rdx", [RSI] = "rsi", [RDI] = "rdi", [RSP] = "rsp", [RBP] = "rbp",
    [R8] = "r8", [R9] = "r9", [R10] = "r10", [R11] = "r11", [R12] = "r12", [R13] = "r13", [R14] = "r14", [R15] = "r15",
    [RIP] = "rip", [EFLAGS] = "eflags",
    [CS] = "cs", [DS] = "ds", [ES] = "es", [FS] = "fs", [GS] = "gs", [SS] = "ss",
    [LDTR] = "ldtr", [TR] = "tr", [GDTR_BASE] = "gdtr_base", [GDTR_LIMIT] = "gdtr_limit", [IDTR_BASE] = "idtr_base", [IDTR_LIMIT] = "idtr_limit",
    [CR0] = "cr0", [CR2] = "cr2", [CR3] = "cr3", [CR4] = "cr4",
    [IA32_KERNEL_GS_BASE] = "ia32_kernel_gs_base",
    [IA32_EFER] = "ia32_efer", [XCR0] = "xcr0",
    [IA32_STAR] = "ia32_star", [IA32_CSTAR] = "ia32_cstar", [IA32_LSTAR] = "ia32_lstar",
    [IA32_SYSENTER_EIP] = "ia32_sysenter_eip", [IA32_SYSENTER_CS] = "ia32_sysenter_cs", [IA32_SYSENTER_ESP] = "ia32_sysenter_esp",
    [DR6] = "dr6", [DR7] = "dr7"
};

/*
 * Xen expects segment attribute bits in the following format
 */
union arb {
        struct {
            uint16_t type:4; // 0-3
            uint16_t s:   1; // 4
            uint16_t dpl: 2; // 5-6
            uint16_t p:   1; // 7
            uint16_t avl: 1; // 8
            uint16_t l:   1; // 9
            uint16_t db:  1; // 10
            uint16_t g:   1; // 11
            uint16_t pad: 4; // 12-15
        };
        uint16_t _u;
} arb;

/*
 * https://sandpile.org/x86/desc.htm
 */
uint16_t convert_segment_arbytes(uint32_t attr)
{
    union arb arb;
    arb._u = 0;

    arb.type = (attr >> 8) & 0b1111;
    arb.s    = !!(attr & (1u << 12));
    arb.dpl  = (attr >> 13) & 0b11;
    arb.p    = !!(attr & (1u << 15));
    arb.avl  = !!(attr & (1u << 20));
    arb.l    = !!(attr & (1u << 21));
    arb.db   = !!(attr & (1u << 22));
    arb.g    = !!(attr & (1u << 23));

    return arb._u;
}

CPUState *get_regs_vmcore(char *regmap, char *vmcore)
{
    /* Read in the register map */
    CPUState *cpu = NULL;
    FILE *vmcoref = NULL;
    char *mapline = NULL;
    gchar **regmapline = NULL;

    FILE *regmapf = fopen(regmap, "r");
    if ( !regmapf )
        goto done;

    size_t len;
    size_t read = getline(&mapline, &len, regmapf);
    if ( read == -1 )
        goto done;

    regmapline = g_strsplit(mapline, " ", 2);

    if ( !regmapline )
        goto done;

    uint64_t foffset = strtoull(regmapline[0], NULL, 16);
    size_t size = strtoull(regmapline[1], NULL, 16);

    if ( size % sizeof(CPUState) )
    {
        printf("Size of CPUState in vmcore file is incorrect, expected multiple of %lu, got %lu\n", sizeof(CPUState), size);
        goto done;
    }

    vmcoref = fopen(vmcore, "r");
    if ( !vmcoref )
        goto done;

    if (fseek(vmcoref, foffset, SEEK_SET) != 0)
        goto done;

    cpu = g_malloc0(sizeof(CPUState));
    if ( !cpu )
        goto done;

    read = fread(cpu, sizeof(unsigned char), sizeof(CPUState), vmcoref);

    if ( read == -1 )
    {
        g_free(cpu);
        cpu = NULL;
        goto done;
    }

    if ( cpu->version != 1 && cpu->size != sizeof(CPUState) )
    {
        printf("Recorded CPUState is not correct version or size: %u %u\n", cpu->version, cpu->size);
        g_free(cpu);
        cpu = NULL;
        goto done;
    }

    cpu->cs.flags = convert_segment_arbytes(cpu->cs.flags);
    cpu->ds.flags = convert_segment_arbytes(cpu->ds.flags);
    cpu->es.flags = convert_segment_arbytes(cpu->es.flags);
    cpu->ss.flags = convert_segment_arbytes(cpu->ss.flags);
    cpu->gs.flags = convert_segment_arbytes(cpu->gs.flags);
    cpu->fs.flags = convert_segment_arbytes(cpu->fs.flags);
    cpu->tr.flags = convert_segment_arbytes(cpu->tr.flags);
    cpu->idt.flags = convert_segment_arbytes(cpu->idt.flags);

done:
    if ( vmcoref )
        fclose(vmcoref);
    if ( regmapf )
        fclose(regmapf);
    if ( mapline )
        free(mapline);
    if ( regmapline )
        g_strfreev(regmapline);

    return cpu;
}

CPUState *get_regs_csv(char *reg)
{
    CPUState *cpu = NULL;
    FILE *regf = fopen(reg, "r");
    if ( !regf )
        goto done;

    cpu = g_malloc0(sizeof(CPUState));
    if ( !cpu )
        goto done;

    size_t len = 0;
    char *regline = NULL;

    while (getline(&regline, &len, regf) != -1)
    {
        gchar** line = g_strsplit(regline, ",", 0);
        bool keep_looking = true;

        for (unsigned int i=0; i<__MAX_REG && keep_looking; i++)
        {
            if ( !(keep_looking = strcmp(line[0], reg_names[i])) )
            {
                switch(i) {
                case RAX:
                    cpu->rax = strtoull(line[1], NULL, 0);
                    break;
                case RBX:
                    cpu->rbx = strtoull(line[1], NULL, 0);
                    break;
                case RCX:
                    cpu->rcx = strtoull(line[1], NULL, 0);
                    break;
                case RDX:
                    cpu->rdx = strtoull(line[1], NULL, 0);
                    break;
                case RSI:
                    cpu->rsi = strtoull(line[1], NULL, 0);
                    break;
                case RDI:
                    cpu->rdi = strtoull(line[1], NULL, 0);
                    break;
                case RSP:
                    cpu->rsp = strtoull(line[1], NULL, 0);
                    break;
                case RBP:
                    cpu->rbp = strtoull(line[1], NULL, 0);
                    break;
                case RIP:
                    cpu->rip = strtoull(line[1], NULL, 0);
                    break;
                case R8:
                    cpu->r8 = strtoull(line[1], NULL, 0);
                    break;
                case R9:
                    cpu->r9 = strtoull(line[1], NULL, 0);
                    break;
                case R10:
                    cpu->r10 = strtoull(line[1], NULL, 0);
                    break;
                case R11:
                    cpu->r11 = strtoull(line[1], NULL, 0);
                    break;
                case R12:
                    cpu->r12 = strtoull(line[1], NULL, 0);
                    break;
                case R13:
                    cpu->r13 = strtoull(line[1], NULL, 0);
                    break;
                case R14:
                    cpu->r14 = strtoull(line[1], NULL, 0);
                    break;
                case R15:
                    cpu->r15 = strtoull(line[1], NULL, 0);
                    break;
                case EFLAGS:
                    cpu->rflags = strtoull(line[1], NULL, 0);
                    break;
                case CS:
                    cpu->cs.selector = strtoull(line[1], NULL, 0);
                    cpu->cs.base = strtoull(line[2], NULL, 0);
                    cpu->cs.limit = strtoull(line[3], NULL, 0);
                    cpu->cs.flags = strtoull(line[4], NULL, 0);
                    break;
                case DS:
                    cpu->ds.selector = strtoull(line[1], NULL, 0);
                    cpu->ds.base = strtoull(line[2], NULL, 0);
                    cpu->ds.limit = strtoull(line[3], NULL, 0);
                    cpu->ds.flags = strtoull(line[4], NULL, 0);
                    break;
                case ES:
                    cpu->es.selector = strtoull(line[1], NULL, 0);
                    cpu->es.base = strtoull(line[2], NULL, 0);
                    cpu->es.limit = strtoull(line[3], NULL, 0);
                    cpu->es.flags = strtoull(line[4], NULL, 0);
                    break;
                case FS:
                    cpu->fs.selector = strtoull(line[1], NULL, 0);
                    cpu->fs.base = strtoull(line[2], NULL, 0);
                    cpu->fs.limit = strtoull(line[3], NULL, 0);
                    cpu->fs.flags = strtoull(line[4], NULL, 0);
                    break;
                case GS:
                    cpu->gs.selector = strtoull(line[1], NULL, 0);
                    cpu->gs.base = strtoull(line[2], NULL, 0);
                    cpu->gs.limit = strtoull(line[3], NULL, 0);
                    cpu->gs.flags = strtoull(line[4], NULL, 0);
                    break;
                case SS:
                    cpu->ss.selector = strtoull(line[1], NULL, 0);
                    cpu->ss.base = strtoull(line[2], NULL, 0);
                    cpu->ss.limit = strtoull(line[3], NULL, 0);
                    cpu->ss.flags = strtoull(line[4], NULL, 0);
                    break;
                case LDTR:
                    cpu->ldt.selector = strtoull(line[1], NULL, 0);
                    cpu->ldt.base = strtoull(line[2], NULL, 0);
                    cpu->ldt.limit = strtoull(line[3], NULL, 0);
                    cpu->ldt.flags = strtoull(line[4], NULL, 0);
                    break;
                case TR:
                    cpu->tr.selector = strtoull(line[1], NULL, 0);
                    cpu->tr.base = strtoull(line[2], NULL, 0);
                    cpu->tr.limit = strtoull(line[3], NULL, 0);
                    cpu->tr.flags = strtoull(line[4], NULL, 0);
                    break;
                case GDTR_BASE:
                    cpu->gdt.base = strtoull(line[1], NULL, 0);
                    break;
                case GDTR_LIMIT:
                    cpu->gdt.limit = strtoull(line[1], NULL, 0);
                    break;
                case IDTR_BASE:
                    cpu->idt.base = strtoull(line[1], NULL, 0);
                    break;
                case IDTR_LIMIT:
                    cpu->idt.limit = strtoull(line[1], NULL, 0);
                    break;
                case CR0:
                    cpu->cr[0] = strtoull(line[1], NULL, 0);
                    break;
                case CR2:
                    cpu->cr[2] = strtoull(line[1], NULL, 0);
                    break;
                case CR3:
                    cpu->cr[3] = strtoull(line[1], NULL, 0);
                    break;
                case CR4:
                    cpu->cr[4] = strtoull(line[1], NULL, 0);
                    break;
                case IA32_KERNEL_GS_BASE:
                    cpu->kernel_gs_base = strtoull(line[1], NULL, 0);
                    break;
                case IA32_EFER:
                    cpu->efer = strtoull(line[1], NULL, 0);
                    break;
                case XCR0:
                    cpu->xcr0 = strtoull(line[1], NULL, 0);
                    break;
                case IA32_STAR:
                    cpu->star = strtoull(line[1], NULL, 0);
                    break;
                case IA32_CSTAR:
                    cpu->star = strtoull(line[1], NULL, 0);
                    break;
                case IA32_LSTAR:
                    cpu->star = strtoull(line[1], NULL, 0);
                    break;
                case IA32_SYSENTER_EIP:
                    cpu->sysenter_eip = strtoull(line[1], NULL, 0);
                    break;
                case IA32_SYSENTER_CS:
                    cpu->sysenter_cs = strtoull(line[1], NULL, 0);
                    break;
                case IA32_SYSENTER_ESP:
                    cpu->sysenter_esp = strtoull(line[1], NULL, 0);
                    break;
                case DR6:
                    cpu->dr6 = strtoull(line[1], NULL, 0);
                    break;
                case DR7:
                    cpu->dr7 = strtoull(line[1], NULL, 0);
                    break;
                };
            }
        }

        g_strfreev(line);
    }

done:
    return cpu;
}

/*
 * Get the existing Xen hvm context, then overwrite the CPU registers
 * with the ones from the register save file.
 */
bool load_regs(char *reg, char *vmcore)
{
    CPUState *cpu = NULL;
    bool ret = false;
    size_t ctxsize = xc_domain_hvm_getcontext(xc, domainid, 0, 0);

    if (ctxsize <= 0)
        return false;

    uint8_t *buf = malloc(ctxsize);
    if ( !buf )
        return false;

    if (xc_domain_hvm_getcontext(xc, domainid, buf, ctxsize) < 0)
        goto done;

    size_t off = 0;
    struct hvm_save_descriptor *desc = NULL;
    HVM_SAVE_TYPE(CPU) *regs = NULL;

    while (off < ctxsize) {
        desc = (struct hvm_save_descriptor *)(buf + off);

        off += sizeof (struct hvm_save_descriptor);

        if (desc->typecode == HVM_SAVE_CODE(CPU) ) {
            if ( desc->instance == 0 /* vcpu */) {
                regs = (HVM_SAVE_TYPE(CPU) *)(buf + off);
                break;
            }
        }

        off += desc->length;
    }

    if (!regs) {
        printf("No vCPU context found in target VM\n");
        goto done;
    }

    /*
     * The CPUState info may come from either a csv file
     * or in binary form embedded in the vmcore file.
     */
    cpu = g_strrstr(reg, ".csv") ? get_regs_csv(reg) : get_regs_vmcore(reg, vmcore);

    regs->rax = cpu->rax;
    regs->rbx = cpu->rbx;
    regs->rcx = cpu->rcx;
    regs->rdx = cpu->rdx;
    regs->rdi = cpu->rdi;
    regs->rsi = cpu->rsi;
    regs->rip = cpu->rip;
    regs->rsp = cpu->rsp;
    regs->rbp = cpu->rbp;
    regs->r8 = cpu->r8;
    regs->r9 = cpu->r9;
    regs->r10 = cpu->r10;
    regs->r11 = cpu->r11;
    regs->r12 = cpu->r12;
    regs->r13 = cpu->r13;
    regs->r14 = cpu->r14;
    regs->r15 = cpu->r15;
    regs->rflags = cpu->rflags;
    regs->cr0 = cpu->cr[0];
    regs->cr2 = cpu->cr[2];
    regs->cr3 = cpu->cr[3];

#define X86_CR4_UMIP       0x00000800
#define X86_CR4_VMXE       0x00002000
#define X86_CR4_PKE        0x00400000
#define X86_CR4_CET        0x00800000
    regs->cr4 = cpu->cr[4] & ~(X86_CR4_UMIP | X86_CR4_VMXE | X86_CR4_PKE | X86_CR4_CET);

    regs->msr_efer = cpu->efer;
    regs->msr_star = cpu->star;
    regs->msr_cstar = cpu->cstar;
    regs->msr_lstar = cpu->lstar;
    regs->dr6 = cpu->dr6;
    regs->dr7 = cpu->dr7;

    regs->sysenter_cs = cpu->sysenter_cs;
    regs->sysenter_eip = cpu->sysenter_eip;
    regs->sysenter_esp = cpu->sysenter_esp;

    regs->shadow_gs = cpu->kernel_gs_base;

    regs->tr_base = cpu->tr.base;
    regs->tr_limit = cpu->tr.limit;
    regs->ldtr_base = cpu->ldt.base;
    regs->ldtr_limit = cpu->ldt.limit;
    regs->gdtr_base = cpu->gdt.base;
    regs->gdtr_limit = cpu->gdt.limit;
    regs->idtr_base = cpu->idt.base;
    regs->idtr_limit = cpu->idt.limit;

    regs->cs_sel = cpu->cs.selector;
    regs->cs_base = cpu->cs.base;
    regs->cs_limit = cpu->cs.limit;
    regs->cs_arbytes = cpu->cs.flags;

    regs->ds_sel = cpu->ds.selector;
    regs->ds_base = cpu->ds.base;
    regs->ds_limit = cpu->ds.limit;
    regs->ds_arbytes = cpu->ds.flags;

    regs->es_sel = cpu->es.selector;
    regs->es_base = cpu->es.base;
    regs->es_limit = cpu->es.limit;
    regs->es_arbytes = cpu->es.flags;

    regs->fs_sel = cpu->fs.selector;
    regs->fs_base = cpu->fs.base;
    regs->fs_limit = cpu->fs.limit;
    regs->fs_arbytes = cpu->fs.flags;

    regs->gs_sel = cpu->gs.selector;
    regs->gs_base = cpu->gs.base;
    regs->gs_limit = cpu->gs.limit;
    regs->gs_arbytes = cpu->gs.flags;

    regs->ss_sel = cpu->ss.selector;
    regs->ss_base = cpu->ss.base;
    regs->ss_limit = cpu->ss.limit;
    regs->ss_arbytes = cpu->ss.flags;

    ret = xc_domain_hvm_setcontext(xc, domainid, buf, ctxsize) == 0;

    printf("Set vCPU context: %s\n", ret ? "success" : "failure");

done:
    g_free(cpu);
    free(buf);

    return ret;
}

bool load_mem(char *map, char *memf)
{
    FILE *mapfp = fopen(map, "r");
    if (mapfp == NULL)
        return false;

    FILE *fp = fopen(memf, "r");
    if ( !fp )
        return false;

    size_t len = 0, read;
    char *mapline = NULL;

    while (getline(&mapline, &len, mapfp) != -1) {
        unsigned long s = 0, f = 0;
        gchar **split = g_strsplit(mapline, " ", 3);
        size_t foffset = strtoull(split[0], NULL, 16);
        size_t moffset = strtoull(split[1], NULL, 16);
        size_t size = strtoull(split[2], NULL, 16);
        g_strfreev(split);

        printf("Loading memory from file offset: 0x%lx to memory offset: 0x%lx Size: 0x%lx\n", foffset, moffset, size);

        if (fseek(fp, foffset, SEEK_SET) != 0)
            return false;

        for ( unsigned long loop = 0; loop < size; loop += XC_PAGE_SIZE )
        {
            uint8_t page[XC_PAGE_SIZE] = {0};

            size_t read = fread(&page, sizeof(uint8_t), XC_PAGE_SIZE, fp);
            if ( read != XC_PAGE_SIZE )
            {
                printf("Failed to read page size from file, got only %lu\n", read);
                if ( fseek(fp, ftell(fp) + XC_PAGE_SIZE - read, SEEK_SET) )
                    return false;
            }

            void *mem = xc_map_foreign_range(xc, domainid, XC_PAGE_SIZE, PROT_WRITE, (moffset + loop) >> 12);
            if ( !mem )
            {
                f++;
                continue;
            }

            s++;
            memcpy(mem, &page, read);
            munmap(mem, XC_PAGE_SIZE);
        }

        printf("Loaded pages: %lu Failed: %lu\n", s, f);
    }

    fclose(mapfp);
    fclose(fp);

    return true;
}

int main(int argc, char** argv)
{
    if (argc < 5 )
    {
        printf("%s <domainid> <regmap|regs.csv> <memmap> <vmcore>\n", argv[0]);
        return 1;
    }

    domainid = atoi(argv[1]);
    char *regs = argv[2];
    char *memmap = argv[3];
    char *vmcore = argv[4];

    xc = xc_interface_open(0,0,0);

    if ( load_regs(regs, vmcore) && load_mem(memmap, vmcore) )
        printf("VM transplanting successful\n");

    xc_interface_close(xc);
}
