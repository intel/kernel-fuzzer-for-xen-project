/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include "private.h"
#include "sink.h"

struct kasan_report_extra_data {
    emul_insn_t emul_insn;
    addr_t internal_addr;
    addr_t internal_offset;
};

/*
 * Some kernel codes would use kasan_disable_current & kasan_enable_current
 * to disable & enable the kasan.
 * Respecting it could prevent the false alarm in the fuzzing report.
 */
bool kasan_report_init(vmi_instance_t vmi, struct sink *s)
{
    addr_t vaddr, offset, ksalr;

    if ( s->extra->data )
    {
        printf("Initialized the kasan_report twice\n");
        return false;
    }

    struct kasan_report_extra_data *data = malloc(sizeof(struct kasan_report_extra_data));
    s->extra->data = data;

    data->emul_insn.dont_free = 1;
    if ( VMI_FAILURE == vmi_read_pa(vmi, s->paddr, 15, &data->emul_insn.data, NULL) )
    {
        printf("Failed to read %s PA 0x%lx\n", s->function, s->paddr);
        return false;
    }

    if ( VMI_FAILURE == vmi_translate_ksym2v(vmi, "current_task", &vaddr) )
    {
        printf("Failed to get current_task\n");
        return false;
    }
    if ( VMI_FAILURE == vmi_get_kernel_struct_offset(vmi, "task_struct", "kasan_depth", &offset) )
    {
        printf("Failed to get kasan_depth\n");
        return false;
    }
    if ( VMI_FAILURE == vmi_get_offset(vmi, "linux_kaslr", &ksalr) )
    {
        printf("Failed to get linux_kaslr\n");
        return false;
    }
    data->internal_addr = vaddr - ksalr;
    data->internal_offset = offset;

    return true;
}

sink_cb_response_t kasan_report_cb(vmi_instance_t vmi, vmi_event_t *event, event_response_t *rsp, struct sink *s)
{
    struct kasan_report_extra_data *data = s->extra->data;
    addr_t current_task;
    unsigned int kasan_depth;
    reg_t base;

    if ( !data ) {
        printf("kasan_report isn't initialized\n");
        return REPORT_CRASH;
    }

    base = event->x86_regs->gs_base;

    if ( VMI_FAILURE == vmi_read_addr_va(vmi, base + data->internal_addr, 0, &current_task) )
    {
        printf("Failed to read current_task\n");
        return REPORT_CRASH;
    }

    if ( VMI_FAILURE == vmi_read_32_va(vmi, current_task + data->internal_offset, 0, &kasan_depth) )
    {
        printf("Failed to read kasan_depth\n");
        return REPORT_CRASH;
    }

    if ( kasan_depth )
    {
        event->interrupt_event.reinject = 0;
        event->emul_insn = &data->emul_insn;
        *rsp = VMI_EVENT_RESPONSE_EMULATE | VMI_EVENT_RESPONSE_SET_EMUL_INSN;

        if ( VMI_EVENT_SINGLESTEP == event->type )
            *rsp |= VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;

        return CONTINUE;
    }

    return REPORT_CRASH;
}

struct sink_extra kasan_report_extra = {
    .init = kasan_report_init,
    .cb = kasan_report_cb,
};
