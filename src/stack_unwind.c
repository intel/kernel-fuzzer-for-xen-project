/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <glib.h>
#include <libvmi/libvmi.h>
#include <libunwind.h>

struct wrapper
{
    vmi_instance_t vmi;
    x86_registers_t *regs;
    page_mode_t pm;
};

static int _unw_access_mem(unw_addr_space_t as, unw_word_t addr, unw_word_t *valp, int __write, void *arg)
{
    struct wrapper *w = (struct wrapper *)arg;
    ACCESS_CONTEXT(ctx);
    ctx.pm = w->pm;
    ctx.tm = VMI_TM_PROCESS_PT;
    ctx.pt = w->regs->cr3;
    ctx.addr = addr;

    addr_t tmp = 0;

    if ( VMI_FAILURE == vmi_read_64(w->vmi, &ctx, &tmp) )
    {
        printf("Failed to read mem at 0x%lx\n", addr);
        return 1;
    }

    *valp = tmp;
    return 0;
}

static int _unw_access_reg(unw_addr_space_t as, unw_regnum_t regnum, unw_word_t *valp, int __write, void *arg)
{
    struct wrapper *w = (struct wrapper *)arg;

    switch(regnum)
    {
        case UNW_X86_64_RBP:
            *valp = w->regs->rbp;
            break;
        case UNW_X86_64_RSP:
            *valp = w->regs->rsp;
            break;
        case UNW_X86_64_RIP:
            *valp = w->regs->rip;
            break;
        default:
            printf("Unsupported reg: %i\n", regnum);
            return 1;
    };

    return 0;
}

static int _unw_resume(unw_addr_space_t as, unw_cursor_t *cu, void *arg)
{
    return -UNW_EINVAL;
}

static int _unw_access_fpreg(unw_addr_space_t as, unw_regnum_t num, unw_fpreg_t *val, int w, void *arg)
{
    return -UNW_ENOINFO;
}

static int _unw_find_proc_info(unw_addr_space_t as, unw_word_t ip, unw_proc_info_t *pi, int i, void *arg)
{
    return -UNW_ENOINFO;
}

static void _unw_put_info(unw_addr_space_t as, unw_proc_info_t *pi, void *arg)
{
}

static int _unw_get_dyn_info(unw_addr_space_t as, unw_word_t *d, void *arg)
{
    return -UNW_ENOINFO;
}

static int _unw_get_proc_name(unw_addr_space_t as, unw_word_t addr, char *b, size_t bl, unw_word_t *off, void *arg)
{
    return -UNW_ENOINFO;
}

unw_addr_space_t unw_as;
unw_accessors_t unw_ap = {
    .resume = _unw_resume,
    .access_fpreg = _unw_access_fpreg,
    .find_proc_info = _unw_find_proc_info,
    .put_unwind_info = _unw_put_info,
    .get_dyn_info_list_addr = _unw_get_dyn_info,
    .get_proc_name = _unw_get_proc_name,

    /* really we only need these two */
    .access_mem = _unw_access_mem,
    .access_reg = _unw_access_reg
};

bool stack_unwind_init(void)
{
    return NULL != (unw_as = unw_create_addr_space(&unw_ap, 0));
}

GSList *stack_unwind(vmi_instance_t vmi, x86_registers_t *regs, page_mode_t pm)
{
    struct wrapper w = {
        .vmi = vmi,
        .regs = regs,
        .pm = pm
    };

    GSList *stack = NULL;
    unw_cursor_t unw_cursor;
    unw_init_remote(&unw_cursor, unw_as, &w);
    int rc;

    do {
        unw_word_t pc;
        unw_get_reg(&unw_cursor, UNW_REG_IP, &pc);

        stack = g_slist_prepend(stack, GSIZE_TO_POINTER(pc));
    } while( (rc = unw_step(&unw_cursor)) > 0 );

    if ( rc < 0 )
        printf("Stack unwind error: %i\n", rc);

    return stack;
}

void stack_unwind_clear(void)
{
    unw_destroy_addr_space(unw_as);
}
