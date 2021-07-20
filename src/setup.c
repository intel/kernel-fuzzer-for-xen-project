/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include "private.h"

extern int interrupted;
extern bool parent_ready;
extern bool extended_mark;
extern unsigned int magic_mark;

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

static void decode_extended_harness(const x86_registers_t *regs, const cpuid_event_t* cpuid_event, addr_t *address, size_t *size)
{
    *address = regs->rsi;
    if ( cpuid_event && size )
        *size = cpuid_event->subleaf;
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
            addr_t buf_addr;
            size_t buf_size;
            decode_extended_harness(event->x86_regs, &event->cpuid_event, &buf_addr, &buf_size);

            printf("Target buffer & size: 0x%lx %lu\n", buf_addr, buf_size);
        }

        cpuid_done(vmi, event);
    }

    event->x86_regs->rip = rip;

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

static bool get_auto_address(vmi_instance_t vmi, addr_t *address)
{
    registers_t regs = {0};
    uint16_t insn = 0;

    if ( vmi_get_vcpuregs(vmi, &regs, 0) )
        return false;

    /* Best-effort rewind by directly comparing $(RIP-2) with CPUID opcode */
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .pt = regs.x86.cr3,
        .addr = regs.x86.rip - 2,
    );
    if ( vmi_read_16(vmi, &ctx, &insn) )
        return false;
    if ( insn == 0xa20f )
    {
        decode_extended_harness(&regs.x86, NULL, address, NULL);
        return true;
    }
    return false;
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

    if ( !setup_vmi(&parent_vmi, domain, domid, NULL, setup, auto_address ) )
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
    else if ( auto_address )
    {
        parent_ready = get_auto_address(parent_vmi, &address);
        if ( !parent_ready )
            fprintf(stderr, "Failed to auto infer address. Was the VM setup with --extended-mark?\n");
        else
          printf("Auto inferred Input address 0x%lx\n", address);
    } else
        parent_ready = true;

    vmi_destroy(parent_vmi);
    parent_vmi = NULL;

    printf("Parent %s ready\n", parent_ready ? "is" : "is not");

    return parent_ready;
}
