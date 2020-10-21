/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include "private.h"

extern int interrupted;
extern bool parent_ready;
extern bool extended_cpuid;

static vmi_event_t cpuid_event, cc_event;

static size_t buf_size;
static addr_t buf_addr;
static addr_t rip;

static void cpuid_done(vmi_instance_t vmi, vmi_event_t *event)
{
    vmi_pause_vm(vmi);
    vmi_clear_event(vmi, event, NULL);

    vmi_set_vcpureg(vmi, rip, RIP, event->vcpu_id);

    parent_ready = 1;
    interrupted = 1;
}

static event_response_t start_cpuid_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    rip = event->x86_regs->rip + event->cpuid_event.insn_length;

    if ( event->cpuid_event.leaf == magic_cpuid )
    {
        printf("Got start cpuid callback with leaf: 0x%x subleaf: 0x%x\n",
               event->cpuid_event.leaf, event->cpuid_event.subleaf);

        if ( extended_cpuid )
            buf_size = event->cpuid_event.subleaf;
        else
            cpuid_done(vmi, event);
    }
    else
    if ( buf_size )
    {
        buf_addr = event->cpuid_event.leaf;
        buf_addr <<= 32;
        buf_addr |= event->cpuid_event.subleaf;

        printf("Target buffer & size: 0x%lx %lu\n", buf_addr, buf_size);
        cpuid_done(vmi, event);
    }

    event->x86_regs->rip = rip;

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

static event_response_t start_cc_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = event->x86_regs->cr3,
        .addr = event->x86_regs->rip
    };

    if ( VMI_SUCCESS == vmi_write_8(vmi, &ctx, &start_byte) )
    {
        event->interrupt_event.reinject = 0;
        parent_ready = 1;
    } else
        event->interrupt_event.reinject = 1;

    vmi_pause_vm(vmi);
    interrupted = 1;
    vmi_clear_event(vmi, event, NULL);

    printf("Parent VM is paused at the breakpoint location\n");

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

        printf("Waiting for harness start (cpuid with leaf 0x%x)\n", magic_cpuid);

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
    if ( !setup_vmi(&parent_vmi, domain, domid, NULL, setup, false, false) )
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
    else
        parent_ready = true;

    vmi_destroy(parent_vmi);
    parent_vmi = NULL;

    printf("Parent %s ready\n", parent_ready ? "is" : "is not");

    return parent_ready;
}
