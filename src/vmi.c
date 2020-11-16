/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include "vmi.h"

extern addr_t target_pagetable;
extern addr_t start_rip;
extern os_t os;
extern int interrupted;
extern page_mode_t pm;

bool setup_vmi(vmi_instance_t *vmi, char* domain, uint64_t domid, char* json, bool init_events, bool init_os, bool init_paging)
{
    printf("Init vmi, init_events: %i init_os %i init_paging %i domain %s domid %lu\n",
           init_events, init_os, init_paging, domain, domid);

    vmi_mode_t mode = (init_events ? VMI_INIT_EVENTS : 0) |
                      (domain ? VMI_INIT_DOMAINNAME : VMI_INIT_DOMAINID);

    const void *d = domain ?: (void*)&domid;

    if ( VMI_FAILURE == vmi_init(vmi, VMI_XEN, d, mode, NULL, NULL) )
        return false;

    if ( init_os )
    {
        if ( VMI_OS_UNKNOWN == (os = vmi_init_os(*vmi, VMI_CONFIG_JSON_PATH, json, NULL)) )
        {
            vmi_destroy(*vmi);
            return false;
        }

        pm = vmi_get_page_mode(*vmi, 0);
    }
    else
    if ( init_paging && VMI_PM_UNKNOWN == (pm = vmi_init_paging(*vmi, 0)) )
    {
        vmi_destroy(*vmi);
        return false;
    }

    registers_t regs = {0};
    if ( VMI_FAILURE == vmi_get_vcpuregs(*vmi, &regs, 0) )
    {
        vmi_destroy(*vmi);
        return false;
    }

    target_pagetable = regs.x86.cr3;
    start_rip = regs.x86.rip;

    return true;
}

void loop(vmi_instance_t vmi)
{
    if ( !vmi )
        return;

    vmi_resume_vm(vmi);

    while (!interrupted)
    {
        if ( vmi_events_listen(vmi, 500) == VMI_FAILURE )
        {
            fprintf(stderr, "Error in vmi_events_listen!\n");
            break;
        }
    }

    interrupted = 0;
}
