/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include "vmi.h"
#include "stack_unwind.h"

vmi_instance_t vmi;

int main(int argc, char** argv)
{
    if ( argc < 2 )
    {
        printf("Usage: %s <domid>\n", argv[0]);
        return -1;
    }

    int domid = atoi(argv[1]);

    if ( VMI_FAILURE == vmi_init(&vmi, VMI_XEN, &domid, VMI_INIT_DOMAINID, NULL, NULL) )
        return 0;

    vmi_pause_vm(vmi);
    stack_unwind_init();

    long unsigned int vcpus = vmi_get_num_vcpus(vmi);
    while (vcpus--)
    {
        registers_t regs;
        if ( VMI_FAILURE == vmi_get_vcpuregs(vmi, &regs, vcpus) )
            continue;

        GSList *stack = stack_unwind(vmi, &regs.x86, vmi_get_page_mode(vmi, vcpus));
        GSList *loop = stack;

        printf("vCPU %lu:\n", vcpus);
        while (loop)
        {
            addr_t ip = GPOINTER_TO_SIZE(loop->data);
            printf("\t0x%lx\n", ip);
            loop = loop->next;
        }

        g_slist_free(stack);
    }

    stack_unwind_clear();
    vmi_resume_vm(vmi);
    vmi_destroy(vmi);

    return 0;
}
