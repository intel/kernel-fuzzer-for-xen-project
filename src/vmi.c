/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <stdlib.h>

#include "vmi.h"

extern addr_t target_pagetable;
extern addr_t start_rip;
extern os_t os;
extern int interrupted;
extern page_mode_t pm;
extern vmi_instance_t vmi;

bool setup_vmi(vmi_instance_t *vmi, char* domain, uint64_t domid, char* json, char *kvmi, bool init_events, bool init_paging)
{
    printf("Init vmi, init_events: %i init_paging %i domain %s domid %lu json %s kvmi %s\n",
           init_events, init_paging, domain, domid, json, kvmi);

    uint64_t options = (init_events ? VMI_INIT_EVENTS : 0) |
                       (domain ? VMI_INIT_DOMAINNAME : VMI_INIT_DOMAINID);
    vmi_mode_t mode = kvmi ? VMI_KVM : VMI_XEN;
    const void *d = domain ?: (void*)&domid;

    vmi_init_data_t *data = NULL;
    if ( kvmi )
    {
        data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
        data->count = 1;
        data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
        data->entry[0].data = kvmi;
    }

    status_t status = vmi_init(vmi, mode, d, options, data, NULL);

    free(data);

    if ( VMI_FAILURE == status )
        return false;

    if ( json )
    {
        if ( VMI_OS_UNKNOWN == (os = vmi_init_os(*vmi, VMI_CONFIG_JSON_PATH, json, NULL)) )
        {
            fprintf(stderr, "Error in vmi_init_os!\n");
            vmi_destroy(*vmi);
            return false;
        }

        pm = vmi_get_page_mode(*vmi, 0);
    }
    else
    if ( init_paging && VMI_PM_UNKNOWN == (pm = vmi_init_paging(*vmi, 0)) )
    {
        fprintf(stderr, "Error in vmi_init_paging!\n");
        vmi_destroy(*vmi);
        return false;
    }

    registers_t regs = {0};
    if ( VMI_FAILURE == vmi_get_vcpuregs(*vmi, &regs, 0) )
    {
        fprintf(stderr, "Error in vmi_get_vcpuregs!\n");
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
