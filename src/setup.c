/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include "private.h"

extern int interrupted;
extern bool parent_ready;
extern bool extended_mark;
extern unsigned int magic_mark;

#define extended_mark_cookie (UINT64_C(0x13371337) << 32)

static vmi_event_t cpuid_event, cc_event;
static addr_t rip;

static void cpuid_done(vmi_instance_t vmi, vmi_event_t *event)
{
    vmi_pause_vm(vmi);
    vmi_clear_event(vmi, event, NULL);

    vmi_set_vcpureg(vmi, rip, RIP, event->vcpu_id);

    parent_ready = 1;
    interrupted = 1;
}

static void stash_extended_mark(vmi_instance_t vmi, unsigned long vcpu, addr_t addr, size_t size)
{
    vmi_set_vcpureg(vmi, extended_mark_cookie | magic_mark, RAX, vcpu);
    vmi_set_vcpureg(vmi, addr, RSI, vcpu);
    vmi_set_vcpureg(vmi, size, RCX, vcpu);
}

static bool pop_extended_mark(vmi_instance_t vmi, unsigned long vcpu, addr_t *addr, size_t *size)
{
    registers_t regs;
    if ( vmi_get_vcpuregs(vmi, &regs, vcpu) )
        return false;
    if ( (regs.x86.rax & 0xffffffff00000000) != extended_mark_cookie )
        return false;
    if ( magic_mark && ((regs.x86.rax & 0xffffffff) != magic_mark) )
        return false;
    *addr = regs.x86.rsi;
    *size = regs.x86.rcx;
    return true;
}

static event_response_t start_cpuid_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    rip = event->x86_regs->rip + event->cpuid_event.insn_length;

    if ( event->cpuid_event.leaf == magic_mark )
    {
        printf("Got start cpuid callback with leaf: 0x%x subleaf: 0x%x\n",
               event->cpuid_event.leaf, event->cpuid_event.subleaf);

        if ( extended_mark )
        {
            addr_t buf_addr = event->x86_regs->rsi;
            size_t buf_size = event->cpuid_event.subleaf;
            stash_extended_mark(vmi, event->vcpu_id, buf_addr, buf_size);

            printf("Target buffer & size: 0x%lx %lu\n", buf_addr, buf_size);
        }

        cpuid_done(vmi, event);
    }

    event->x86_regs->rip = rip;

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

static event_response_t start_cc_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    addr_t pa = (event->interrupt_event.gfn << 12) + event->interrupt_event.offset;
    bool start = true;

    if ( magic_mark && event->x86_regs->rax != magic_mark )
        start = false;

    if ( start && VMI_SUCCESS == vmi_write_8_pa(vmi, pa, &start_byte) )
    {
        event->interrupt_event.reinject = 0;
        parent_ready = 1;
        vmi_pause_vm(vmi);
        interrupted = 1;
        vmi_clear_event(vmi, event, NULL);
        printf("Parent VM is paused at the breakpoint location\n");

        if ( extended_mark )
            printf("Target buffer & size: 0x%lx %lu\n",
                   event->x86_regs->rbx, event->x86_regs->rcx);

    } else
        event->interrupt_event.reinject = 1;

    return 0;
}

static void waitfor_start(vmi_instance_t vmi)
{
    if ( harness_cpuid )
    {
        cpuid_event.version = VMI_EVENTS_VERSION;
        cpuid_event.type = VMI_EVENT_CPUID;
        cpuid_event.callback = start_cpuid_cb;

        if ( VMI_FAILURE == vmi_register_event(vmi, &cpuid_event) )
            return;

        printf("Waiting for harness start (cpuid with leaf 0x%x)\n", magic_mark);

    } else {
        SETUP_INTERRUPT_EVENT(&cc_event, start_cc_cb);

        if ( VMI_FAILURE == vmi_register_event(vmi, &cc_event) )
            return;

        printf("Waiting for harness start (software breakpoint, 0xCC)\n");
    }

    loop(vmi);

    interrupted = 0;

    return;
}

bool make_parent_ready(void)
{
    vmi_instance_t parent_vmi;

    if ( !setup_vmi(&parent_vmi, domain, domid, NULL, setup, false) )
    {
        fprintf(stderr, "Unable to start VMI on domain\n");
        return false;
    }

    vcpus = vmi_get_num_vcpus(parent_vmi);

    if ( vcpus > 1 )
    {
        fprintf(stderr, "The target domain has more then 1 vCPUs: %u, not supported\n", vcpus);
        return false;
    }

    if ( !domid )
        domid = vmi_get_vmid(parent_vmi);

    if ( setup )
        waitfor_start(parent_vmi);
    else if ( extended_mark )
    {
        parent_ready = pop_extended_mark(parent_vmi, 0, &address, &input_limit);
        if ( !parent_ready )
            fprintf(stderr, "Failed to infer input address and limit. Was the VM setup with --extended-mark?\n");
        else
          printf("Auto inferred Input address=0x%lx, input-limit=%zu\n", address, input_limit);
    } else
        parent_ready = true;

    vmi_destroy(parent_vmi);
    parent_vmi = NULL;

    printf("Parent %s ready\n", parent_ready ? "is" : "is not");

    return parent_ready;
}
