/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include <stdint.h>
#include <stdlib.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include "vmi.h"

vmi_instance_t vmi;
os_t os;
page_mode_t pm;
addr_t target_pagetable;
addr_t start_rip;
int interrupted;

static void usage(void)
{
    printf("Usage:\n");
    printf("\t --domid <domid>\n");
    printf("\t --vcpuid <vcpuid>\t(default=0)\n");
}

int main(int argc, char** argv)
{
    int c, long_index = 0;
    const struct option long_opts[] =
    {
        {"help", no_argument, NULL, 'h'},
        {"domid", required_argument, NULL, 'd'},
        {"vcpuid", required_argument, NULL, 'v'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "d:";
    uint32_t domid = 0;
    uint32_t vcpuid = 0; 

    while ((c = getopt_long (argc, argv, opts, long_opts, &long_index)) != -1)
    {
        switch(c)
        {
        case 'd':
            domid = strtoul(optarg, NULL, 0);
            break;
        case 'v':
            vcpuid = strtoul(optarg, NULL, 0);
            break;
        case 'h': /* fall-through */
        default:
            usage();
            return -1;
        };
    }

    if ( !domid )
    {
        usage();
        return -1;
    }

    if ( !setup_vmi(&vmi, NULL, domid, NULL, false, true) )
        return -1;

    pm = vmi_get_page_mode(vmi, vcpuid);
    registers_t regs = {0};
    if ( VMI_SUCCESS == vmi_get_vcpuregs(vmi, &regs, vcpuid) )
    {
        if ( pm == VMI_PM_IA32E )
        {
            printf("RIP: 0x%lx\n"
                   "RAX: 0x%lx\n"
                   "RBX: 0x%lx\n"
                   "RCX: 0x%lx\n"
                   "RDX: 0x%lx\n"
                   "RSI: 0x%lx\n"
                   "RDI: 0x%lx\n"
                   "RBP: 0x%lx\n"
                   "RSP: 0x%lx\n"
                   "R8 : 0x%lx\n"
                   "R9 : 0x%lx\n"
                   "R10: 0x%lx\n"
                   "R11: 0x%lx\n"
                   "R12: 0x%lx\n"
                   "R13: 0x%lx\n"
                   "R14: 0x%lx\n"
                   "R15: 0x%lx\n", 
                   regs.x86.rip, regs.x86.rax, regs.x86.rbx, regs.x86.rcx,
                   regs.x86.rdx, regs.x86.rsi, regs.x86.rdi, regs.x86.rbp,
                   regs.x86.rsp, regs.x86.r8, regs.x86.r9, regs.x86.r10,
                   regs.x86.r11, regs.x86.r12, regs.x86.r13, regs.x86.r14,
                   regs.x86.r15);
        }
        else
        {

            printf("EIP: 0x%x\n"
                   "EAX: 0x%x\n"
                   "EBX: 0x%x\n"
                   "ECX: 0x%x\n"
                   "EDX: 0x%x\n"
                   "ESI: 0x%x\n"
                   "EDI: 0x%x\n"
                   "EBP: 0x%x\n"
                   "ESP: 0x%x\n", 
                   (uint32_t)regs.x86.rip, (uint32_t)regs.x86.rax, 
                   (uint32_t)regs.x86.rbx, (uint32_t)regs.x86.rcx, 
                   (uint32_t)regs.x86.rdx, (uint32_t)regs.x86.rsi, 
                   (uint32_t)regs.x86.rdi, (uint32_t)regs.x86.rbp, 
                   (uint32_t)regs.x86.rsp);
        }
    }
    else
    {
        printf("Can't get VCPU registers :(\n");
        vmi_destroy(vmi);
        return -1;
    }
done:
    vmi_destroy(vmi);
    return 0;
}
