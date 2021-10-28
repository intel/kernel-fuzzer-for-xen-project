/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 *
 */
#include "save-transplant.h"

bool transplant_save_regs(vmi_instance_t vmi, const char *regf)
{
    registers_t regs = {0};

    if ( VMI_FAILURE == vmi_get_vcpuregs(vmi, &regs, 0) )
        return false;

    FILE *f = fopen(regf, "w");
    if ( !f )
        return false;

    printf("Saving registers to %s\n", regf);

    fprintf(f, "rax,0x%lx\n", regs.x86.rax);
    fprintf(f, "rbx,0x%lx\n", regs.x86.rbx);
    fprintf(f, "rcx,0x%lx\n", regs.x86.rcx);
    fprintf(f, "rdx,0x%lx\n", regs.x86.rdx);
    fprintf(f, "rsp,0x%lx\n", regs.x86.rsp);
    fprintf(f, "rbp,0x%lx\n", regs.x86.rbp);
    fprintf(f, "rsi,0x%lx\n", regs.x86.rsi);
    fprintf(f, "rdi,0x%lx\n", regs.x86.rdi);
    fprintf(f, "r8,0x%lx\n", regs.x86.r8);
    fprintf(f, "r9,0x%lx\n", regs.x86.r9);
    fprintf(f, "r10,0x%lx\n", regs.x86.r10);
    fprintf(f, "r11,0x%lx\n", regs.x86.r11);
    fprintf(f, "r12,0x%lx\n", regs.x86.r12);
    fprintf(f, "r13,0x%lx\n", regs.x86.r13);
    fprintf(f, "r14,0x%lx\n", regs.x86.r14);
    fprintf(f, "r15,0x%lx\n", regs.x86.r15);
    fprintf(f, "rip,0x%lx\n", regs.x86.rip);
    fprintf(f, "eflags,0x%lx\n", regs.x86.rflags);
    fprintf(f, "cr0,0x%lx\n", regs.x86.cr0);
    fprintf(f, "cr2,0x%lx\n", regs.x86.cr2);
    fprintf(f, "cr3,0x%lx\n", regs.x86.cr3);
    fprintf(f, "cr4,0x%lx\n", regs.x86.cr4);
    fprintf(f, "ia32_efer,0x%lx\n", regs.x86.msr_efer);
    fprintf(f, "ia32_star,0x%lx\n", regs.x86.msr_star);
    fprintf(f, "ia32_cstar,0x%lx\n", regs.x86.msr_cstar);
    fprintf(f, "ia32_lstar,0x%lx\n", regs.x86.msr_lstar);
    fprintf(f, "ia32_sysenter_eip,0x%lx\n", regs.x86.sysenter_eip);
    fprintf(f, "ia32_sysenter_cs,0x%lx\n", regs.x86.sysenter_cs);
    fprintf(f, "ia32_sysenter_esp,0x%lx\n", regs.x86.sysenter_esp);
    fprintf(f, "dr6,0x%lx\n", regs.x86.dr6);
    fprintf(f, "dr7,0x%lx\n", regs.x86.dr7);

    fprintf(f, "cs,0x%lx,0x%lx,0x%lx,0x%lx\n", regs.x86.cs_sel, regs.x86.cs_base, regs.x86.cs_limit, regs.x86.cs_arbytes);
    fprintf(f, "ds,0x%lx,0x%lx,0x%lx,0x%lx\n", regs.x86.ds_sel, regs.x86.ds_base, regs.x86.ds_limit, regs.x86.ds_arbytes);
    fprintf(f, "es,0x%lx,0x%lx,0x%lx,0x%lx\n", regs.x86.es_sel, regs.x86.es_base, regs.x86.es_limit, regs.x86.es_arbytes);
    fprintf(f, "fs,0x%lx,0x%lx,0x%lx,0x%lx\n", regs.x86.fs_sel, regs.x86.fs_base, regs.x86.fs_limit, regs.x86.fs_arbytes);
    fprintf(f, "gs,0x%lx,0x%lx,0x%lx,0x%lx\n", regs.x86.gs_sel, regs.x86.gs_base, regs.x86.gs_limit, regs.x86.gs_arbytes);
    fprintf(f, "ss,0x%lx,0x%lx,0x%lx,0x%lx\n", regs.x86.ss_sel, regs.x86.ss_base, regs.x86.ss_limit, regs.x86.ss_arbytes);
    fprintf(f, "tr,0x%lx,0x%lx,0x%lx,0x%lx\n", regs.x86.tr_sel, regs.x86.tr_base, regs.x86.tr_limit, regs.x86.tr_arbytes);
    fprintf(f, "ldtr,0x%lx,0x%lx,0x%lx,0x%lx\n", regs.x86.ldt_sel, regs.x86.ldt_base, regs.x86.ldt_limit, regs.x86.ldt_arbytes);

    fprintf(f, "gdtr_base,0x%lx\n", regs.x86.gdtr_base);
    fprintf(f, "gdtr_limit,0x%lx\n", regs.x86.gdtr_limit);
    fprintf(f, "idtr_base,0x%lx\n", regs.x86.idtr_base);
    fprintf(f, "idtr_limit,0x%lx\n", regs.x86.idtr_limit);

    fclose(f);
    return true;
}

static GHashTable* read_memmap(const char *memmap)
{
    FILE *fp = fopen(memmap, "r");
    if ( !fp )
        return NULL;

    GHashTable *t = g_hash_table_new(g_direct_hash, g_direct_equal);
    size_t len = 0;
    char *mapline = NULL;

    while (getline(&mapline, &len, fp) != -1) {
        gchar **split = g_strsplit(mapline, " ", 3);
        size_t moffset = strtoull(split[1], NULL, 16);
        size_t size = strtoull(split[2], NULL, 16);
        g_strfreev(split);

        g_hash_table_insert(t, GSIZE_TO_POINTER(moffset), GSIZE_TO_POINTER(size));
    }

    fclose(fp);
    return t;
}

bool transplant_save_mem(vmi_instance_t vmi, const char *memmap_in, const char *memmap_out, const char *vmcore)
{
    GHashTable *memmapt = read_memmap(memmap_in);
    if ( !memmapt )
        return false;

    FILE *fp = fopen(vmcore, "w");
    if ( !fp )
        return false;

    FILE *fm = fopen(memmap_out, "w");
    if ( !fm )
        return false;

    vmi_pagecache_flush(vmi);

    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init (&iter, memmapt);
    while (g_hash_table_iter_next (&iter, &key, &value))
    {
        addr_t mem = GPOINTER_TO_SIZE(key);
        addr_t size = GPOINTER_TO_SIZE(value);
        addr_t end = mem + size;
        long fpos = ftell(fp);

        printf("Saving memory from 0x%lx to 0x%lx into file %s at offset 0x%lx\n", mem, end, vmcore, fpos);
        fprintf(fm, "0x%lx 0x%lx 0x%lx\n", fpos, mem, size);

        for (; mem < end; mem += VMI_PS_4KB )
        {
            uint8_t page[VMI_PS_4KB] = {0};
            vmi_read_pa(vmi, mem, VMI_PS_4KB, &page, NULL);
            fwrite(&page,VMI_PS_4KB,1,fp);
        }
    }

    g_hash_table_destroy(memmapt);
    fclose(fm);
    fclose(fp);
    return true;
}
