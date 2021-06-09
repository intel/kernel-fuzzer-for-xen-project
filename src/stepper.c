/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include <stdint.h>
#include <stdlib.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <xenctrl.h>
#include <capstone.h>
#include <glib.h>
#include "vmi.h"
#include "signal.h"

vmi_instance_t vmi;
os_t os;
addr_t target_pagetable;
addr_t start_rip;
addr_t stop_rip;
bool loopmode, reset, stop_on_cpuid, stop_on_sysret;
int interrupted;
unsigned long limit, count;
xc_interface *xc;
csh cs_handle;
page_mode_t pm;

static void usage(void)
{
    printf("Usage:\n");
    printf("\t --domid <domid>\n");
    printf("\t --limit <singlestep count>\n");
    printf("\t --loopmode\n");
    printf("\t --stop-on-cpuid\n");
    printf("\t --stop-on-sysret\n");
    printf("\t --stop-on-address <addr>\n");
    printf("\t --reset\n");
}

void print_instruction(vmi_instance_t _vmi, addr_t cr3, addr_t addr, bool *cpuid, bool *sysret)
{
    unsigned char buf[15] = {0};
    cs_insn *insn = NULL;
    size_t read = 0, insn_count = 0;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .pt = cr3,
        .addr = addr
    );

    vmi_read(_vmi, &ctx, 15, buf, &read);

    if ( read )
    {
        insn_count = cs_disasm(cs_handle, buf, read, cr3, 0, &insn);

        if ( cpuid && insn[0].id == X86_INS_CPUID )
            *cpuid = true;
        if ( sysret && insn[0].id == X86_INS_SYSRET )
            *sysret = true;
    }

    printf("%5lu: %16lx  ", count, addr);

    if ( insn_count )
    {
        gchar *str = g_strconcat(insn[0].mnemonic, " ", insn[0].op_str, NULL);
        printf("%-40s\t", str);
        g_free(str);
    } else
        printf("%-40s\t", "-");

    vmi_print_hex(buf, read);

    if ( insn_count )
        cs_free(insn, insn_count);
}

event_response_t tracer_cb(vmi_instance_t _vmi, vmi_event_t *event)
{
    bool cpuid = false;
    bool sysret = false;

    count++;

    print_instruction(_vmi, event->x86_regs->cr3, event->x86_regs->rip, &cpuid, &sysret);

    if ( count >= limit || (stop_on_cpuid && cpuid) || (stop_on_sysret && sysret) || event->x86_regs->rip == stop_rip )
    {
        interrupted = 1;
        vmi_pause_vm(_vmi);
        return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
    }

    return 0;
}

int main(int argc, char** argv)
{
    int c, long_index = 0;
    const struct option long_opts[] =
    {
        {"help", no_argument, NULL, 'h'},
        {"domid", required_argument, NULL, 'd'},
        {"limit", required_argument, NULL, 'L'},
        {"loopmode", no_argument, NULL, 'l'},
        {"reset", no_argument, NULL, 'r'},
        {"stop-on-cpuid", no_argument, NULL, 's'},
        {"stop-on-sysret", no_argument, NULL, 't'},
        {"stop-on-address", required_argument, NULL, 'S'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "d:L:S:hlrst";
    uint32_t domid = 0;

    while ((c = getopt_long (argc, argv, opts, long_opts, &long_index)) != -1)
    {
        switch(c)
        {
        case 'd':
            domid = strtoul(optarg, NULL, 0);
            break;
        case 'L':
            limit = strtoull(optarg, NULL, 0);
            break;
        case 'l':
            loopmode = true;
            break;
        case 'r':
            reset = true;
            break;
        case 's':
            stop_on_cpuid = true;
            break;
        case 't':
            stop_on_sysret = true;
            break;
        case 'S':
            stop_rip = strtoull(optarg, NULL, 0);
            break;
        case 'h': /* fall-through */
        default:
            usage();
            return -1;
        };
    }

    if ( !domid || !limit )
    {
        usage();
        return -1;
    }

    if ( !setup_vmi(&vmi, NULL, domid, NULL, true, true) )
        return -1;

    if ( !(xc = xc_interface_open(0, 0, 0)) )
        goto done;

    if ( cs_open(CS_ARCH_X86, pm == VMI_PM_IA32E ? CS_MODE_64 : CS_MODE_32, &cs_handle) )
        goto done;

    if ( reset && xc_memshr_fork_reset(xc, domid) )
    {
        printf("Failed to reset VM, is it a fork?\n");
        goto done;
    }

    setup_handlers();

    registers_t regs = {0};
    vmi_event_t singlestep_event;
    SETUP_SINGLESTEP_EVENT(&singlestep_event, 1, tracer_cb, 1);

    do {
        vmi_get_vcpuregs(vmi, &regs, 0);

        print_instruction(vmi, regs.x86.cr3, regs.x86.rip, NULL, NULL);

        vmi_toggle_single_step_vcpu(vmi, &singlestep_event, 0, 1);

        vmi_resume_vm(vmi);
        while ( !interrupted && VMI_SUCCESS == vmi_events_listen(vmi, 500) )
        {}

        vmi_toggle_single_step_vcpu(vmi, &singlestep_event, 0, 0);

        if ( loopmode )
        {
            vmi_pagecache_flush(vmi);
            if ( xc_memshr_fork_reset(xc, domid) )
            {
                printf("Failed to reset VM, is it a fork?\n");
                break;
            }
        }

        printf("----------------------------------------\n");
        interrupted = 0;
        count = 0;

        /*
         * Loopmode here is useful to check whether something causes divergence in the path
         * after a reset. There shouldn't be any divergence since after a reset the fork
         * should resume from the same state as before.
         */
    } while ( loopmode );

done:
    if ( xc )
        xc_interface_close(xc);
    cs_close(&cs_handle);
    vmi_destroy(vmi);

    return 0;
}
