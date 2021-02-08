/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 *
 * This tool is intended to be used to quickly profile the Linux kernel's DMA usage.
 * By monitoring DMA memory allocations and removing the underlying EPT permissions
 * this tool prints out all code-sites that touch DMA memory.
 * Start it when the kernel boot is started or supply the kernel virtual address to
 * monitor for accesses manually.
 */
#include <stdint.h>
#include <stdlib.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <glib.h>
#include "vmi.h"
#include "signal.h"

vmi_instance_t vmi;
os_t os;
addr_t target_pagetable;
addr_t start_rip;
addr_t stop_rip;
bool loopmode, reset, stop_on_cpuid;
int interrupted;
unsigned long limit, count;
page_mode_t pm;

addr_t dma_alloc_attrs, ret;
uint8_t cc = 0xCC, ret_backup;
vmi_event_t interrupt_event;
vmi_event_t mem_event;
vmi_event_t singlestep_event;
emul_insn_t emul_insn = { .dont_free = 1 };
GSList *dma_list;

bool stacktrace;
#define STACKTRACE_LIMIT 10
#define KERNEL_64 0xffffffff80000000ULL

static void usage(void)
{
    printf("Usage:\n");
    printf("\t--domain <domain name>\n");
    printf("\t--domid <domain id>\n");
    printf("\t--json <path to kernel debug json>\n");
    printf("\t--stacktrace\n");
    printf("\t--dma <dma address>\n");
}

static void set_dma_permissions(vmi_instance_t vmi, addr_t dma, addr_t cr3, vmi_mem_access_t access)
{
    addr_t gfn;
    vmi_pagetable_lookup(vmi, cr3, dma, &gfn);
    gfn >>= 12;

    if ( VMI_SUCCESS == vmi_set_mem_event(vmi, gfn, access, 0) )
        printf("EPT permissions changed for page at 0x%lx\n", gfn);
}

static void reset_dma_permissions(gpointer data)
{
    addr_t dma = GPOINTER_TO_SIZE(data);
    set_dma_permissions(vmi, dma, target_pagetable, VMI_MEMACCESS_N);
}

static event_response_t singlestep_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    vmi_set_mem_event(vmi, GPOINTER_TO_SIZE(event->data), VMI_MEMACCESS_RW, 0);
    return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
}

static event_response_t mem_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    printf("DMA access! RIP: 0x%lx Mem: 0x%lx %c%c\n",
           event->x86_regs->rip, event->mem_event.gla,
           (event->mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
           (event->mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-');

    /*
     * Let's print the last X kernel-pointer looking values on the stack.
     * Poor mans stack backtrace ¯\_(ツ)_/¯,  gdbsx does the same.
     */
    unsigned int stackrace_limit = STACKTRACE_LIMIT;
    addr_t rsp = event->x86_regs->rsp;

    while ( stacktrace && stackrace_limit > 0 && rsp < event->x86_regs->rsp + 0x1000 )
    {
        addr_t val = 0;
        vmi_read_addr_va(vmi, rsp, 0, &val);

        // TODO: 32-bit?
        if ( val > KERNEL_64 )
        {
            printf("\t 0x%lx\n", val);
            stackrace_limit--;
        }

        rsp += 8;
    }

    vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_N, 0);
    singlestep_event.data = GSIZE_TO_POINTER(event->mem_event.gfn);
    return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
}

/*
 * We breakpoint dma_alloc_attrs to catch all callers, then breakpoint
 * the return site. At the return site we extract the returned DMA address
 * and remove the underlying EPT permission.
 */
static event_response_t int3_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    if ( event->interrupt_event.gla == dma_alloc_attrs )
    {
        addr_t tmp;
        vmi_read_addr_va(vmi, event->x86_regs->rsp, 0, &tmp);

        if ( ret && ret != tmp )
        {
            printf("A different ret was already breakpointed, 0x%lx != 0x%lx!\n", ret, tmp);
            vmi_write_8_va(vmi, ret, 0, &ret_backup);
        }

        ret = tmp;

        vmi_read_8_va(vmi, ret, 0, &ret_backup);
        vmi_write_8_va(vmi, ret, 0, &cc);

        event->interrupt_event.reinject = 0;
        event->emul_insn = &emul_insn;
        return VMI_EVENT_RESPONSE_EMULATE | VMI_EVENT_RESPONSE_SET_EMUL_INSN;
    }
    else if ( event->interrupt_event.gla == ret )
    {
        vmi_write_8_va(vmi, ret, 0, &ret_backup);
        ret = 0;

        printf("DMA allocated @ 0x%lx\n", event->x86_regs->rax);

        dma_list = g_slist_prepend(dma_list, GSIZE_TO_POINTER(event->x86_regs->rax));

        set_dma_permissions(vmi, event->x86_regs->rax, event->x86_regs->cr3, VMI_MEMACCESS_RW);

        event->interrupt_event.reinject = 0;
    }
    else
        event->interrupt_event.reinject = 1;

    return 0;
}

int main(int argc, char** argv)
{
    int c, long_index = 0;
    const struct option long_opts[] =
    {
        {"help", no_argument, NULL, 'h'},
        {"domain", required_argument, NULL, 'd'},
        {"domid", required_argument, NULL, 'i'},
        {"json", required_argument, NULL, 'j'},
        {"dma", required_argument, NULL, 'a'},
        {"stacktrace", no_argument, NULL, 's'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "d:L:l";
    uint32_t domid = 0;
    char *domain = NULL, *json = NULL;

    while ((c = getopt_long (argc, argv, opts, long_opts, &long_index)) != -1)
    {
        switch(c)
        {
        case 'd':
            domain = optarg;
            break;
        case 'i':
            domid = strtoul(optarg, NULL, 0);
            break;
        case 'j':
            json = optarg;
            break;
        case 's':
            stacktrace = true;
            break;
        case 'a':
        {
            addr_t addr = strtoull(optarg, NULL, 0);
            dma_list = g_slist_prepend(dma_list, GSIZE_TO_POINTER(addr));
            break;
        }
        case 'h': /* fall-through */
        default:
            usage();
            return -1;
        };
    }

    if ( (!domid && !domain) || !json )
    {
        usage();
        return -1;
    }

    if ( !setup_vmi(&vmi, domain, domid, json, true, true) )
        return -1;

    vmi_pause_vm(vmi);

    uint64_t rip = 0;
    vmi_get_vcpureg(vmi, &rip, RIP, 0);

    if ( rip < KERNEL_64 )
    {
        printf("VM is not in kernel mode, try again\n");
        goto done;
    }

    if ( vmi_get_num_vcpus(vmi) > 1 )
    {
        printf("More then 1 vCPUs are not supported\n");
        goto done;
    }

    if ( VMI_FAILURE == vmi_translate_ksym2v(vmi, "dma_alloc_attrs", &dma_alloc_attrs) )
        goto done;

    printf("dma_alloc_attrs @ 0x%lx\n", dma_alloc_attrs);

    setup_handlers();

    SETUP_INTERRUPT_EVENT(&interrupt_event, int3_cb);
    if ( VMI_FAILURE == vmi_register_event(vmi, &interrupt_event) )
        goto done;

    SETUP_SINGLESTEP_EVENT(&singlestep_event, 1, singlestep_cb, 1);
    if ( VMI_FAILURE == vmi_register_event(vmi, &singlestep_event) )
        goto done;

    SETUP_MEM_EVENT(&mem_event, ~0ULL, VMI_MEMACCESS_RWX, mem_cb, 1);
    if ( VMI_FAILURE == vmi_register_event(vmi, &mem_event) )
        goto done;

    if ( VMI_FAILURE == vmi_read_va(vmi, dma_alloc_attrs, 0, 15, &emul_insn.data, NULL) )
        goto done;
    if ( VMI_FAILURE == vmi_write_8_va(vmi, dma_alloc_attrs, 0, &cc) )
        goto done;

    GSList *tmp = dma_list;
    while ( tmp )
    {
        addr_t dma = GPOINTER_TO_SIZE(tmp->data);
        set_dma_permissions(vmi, dma, target_pagetable, VMI_MEMACCESS_RW);

        tmp = tmp->next;
    }

    vmi_resume_vm(vmi);

    while ( !interrupted && VMI_SUCCESS == vmi_events_listen(vmi, 500) )
    {}

done:
    if ( dma_alloc_attrs )
        vmi_write_8_va(vmi, dma_alloc_attrs, 0, (uint8_t*)&emul_insn.data);

    g_slist_free_full(dma_list, reset_dma_permissions);

    vmi_resume_vm(vmi);
    vmi_destroy(vmi);

    return 0;
}
