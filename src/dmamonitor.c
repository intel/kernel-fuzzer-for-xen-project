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
bool loopmode;
int interrupted;
unsigned long limit, count;
page_mode_t pm;
char *json;

addr_t dma_alloc_attrs, ret = 0;
size_t alloc_size;
addr_t alloc_dev;
bool alloc_only;
uint8_t cc = 0xCC, ret_backup;
vmi_event_t interrupt_event;
vmi_event_t mem_event;
vmi_event_t singlestep_event;
vmi_event_t reg_event;
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
    printf("\t--alloc-only\n");
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

/*
 * Assume kernel is built with CONFIG_FRAME_POINTER
 */
static void print_stacktrace(x86_registers_t *regs)
{
    ACCESS_CONTEXT(ctx);
    ctx.tm = VMI_TM_PROCESS_PT;
    ctx.pt = regs->cr3;

    unsigned int stackrace_limit = STACKTRACE_LIMIT;
    addr_t frame = regs->rbp;

    if ( regs->rbp == regs->rsp )
        frame += 8;

    /* TODO: 32-bit */
    while ( frame & (1ul<<47) )
    {
        addr_t next_frame = 0, ret = 0;

        ctx.addr = frame;
        vmi_read_addr(vmi, &ctx, &next_frame);

        ctx.addr = frame + 8;
        vmi_read_addr(vmi, &ctx, &ret);

        if ( ret != (ret | VMI_BIT_MASK(47,63)) )
            break;

        printf("\t0x%lx\n", ret);

        frame = next_frame;
    }
}

static event_response_t mem_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    printf("DMA access! RIP: 0x%lx Mem: 0x%lx %c%c\n",
           event->x86_regs->rip, event->mem_event.gla,
           (event->mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
           (event->mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-');

    if ( stacktrace )
        print_stacktrace(event->x86_regs);

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
        addr_t tmp = 0;
        ACCESS_CONTEXT(ctx);
        ctx.tm = VMI_TM_PROCESS_DTB;
        ctx.addr = event->x86_regs->rsp;
        ctx.pt = event->x86_regs->cr3;
        ctx.pm = event->page_mode;

        if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &tmp) )
            printf("Reading stack return failed\n");

        if ( ret && ret != tmp )
        {
            printf("A different ret was already breakpointed, 0x%lx != 0x%lx!\n", ret, tmp);
            vmi_write_8_va(vmi, ret, 0, &ret_backup);
        }

        alloc_dev = event->x86_regs->rdi;
        alloc_size = event->x86_regs->rsi;

        ret = tmp;

        if ( ret )
        {
            vmi_read_8_va(vmi, ret, 0, &ret_backup);
            vmi_write_8_va(vmi, ret, 0, &cc);

            event->interrupt_event.reinject = 0;
            event->emul_insn = &emul_insn;
        }

        return VMI_EVENT_RESPONSE_EMULATE | VMI_EVENT_RESPONSE_SET_EMUL_INSN;
    }
    else if ( event->interrupt_event.gla == ret )
    {
        target_pagetable = event->x86_regs->cr3;
        vmi_write_8_va(vmi, ret, 0, &ret_backup);
        ret = 0;

        printf("DMA allocated @ 0x%lx. Size: %lu. Dev: 0x%lx\n", event->x86_regs->rax, alloc_size, alloc_dev);

        if ( !alloc_only )
        {
            addr_t start = event->x86_regs->rax;

            // Check if allocation is on a 4k page boundary, if yes we'll need to trap both 4k pages
            if ( ((start + alloc_size + 0xfff) >> 12) != ((start + alloc_size) >> 12) )
                alloc_size += 0x1000;

            for ( size_t i = 0; i < alloc_size; i+=0x1000 )
            {
                dma_list = g_slist_prepend(dma_list, GSIZE_TO_POINTER(start + i));
                set_dma_permissions(vmi, start + i, event->x86_regs->cr3, VMI_MEMACCESS_RW);
            }
        }

        event->interrupt_event.reinject = 0;
    }
    else
        event->interrupt_event.reinject = 1;

    return 0;
}

static event_response_t after_cr3_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    event_response_t rc = VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;

    if ( VMI_PM_UNKNOWN == vmi_init_paging(vmi, event->vcpu_id) )
        return rc;

    if ( VMI_OS_UNKNOWN == vmi_init_os(vmi, VMI_CONFIG_JSON_PATH, json, NULL) )
        return rc;

    interrupted = 1337;
    vmi_pause_vm(vmi);

    return rc;
}

static event_response_t cr3_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    /*
     * We can't init the LibVMI OS-bits in the cr3 callback directly
     * so instead we just going to singlestep once and try there.
     *
     * This is because the LibVMI init requires getting the current CR3
     * but since we trapped the mov-to-cr3 the init would still see only
     * the old value.
     */
    return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
}

int main(int argc, char** argv)
{
    int c, long_index = 0;
    const struct option long_opts[] =
    {
        {"domain", required_argument, NULL, 'd'},
        {"domid", required_argument, NULL, 'i'},
        {"json", required_argument, NULL, 'j'},
        {"dma", required_argument, NULL, 'a'},
        {"stacktrace", no_argument, NULL, 's'},
        {"alloc-only", no_argument, NULL, 'o'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "d:i:j:a:soh";
    uint32_t domid = 0;
    char *domain = NULL;

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
        case 'o':
            alloc_only = 1;
            break;
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

    if ( !setup_vmi(&vmi, domain, domid, NULL, true, false) )
    {
        printf("Failed to enable LibVMI\n");
        return -1;
    }

    vmi_pause_vm(vmi);

    if ( vmi_get_num_vcpus(vmi) > 1 )
    {
        printf("More then 1 vCPUs are not supported\n");
        goto done;
    }

    SETUP_INTERRUPT_EVENT(&interrupt_event, int3_cb);
    if ( VMI_FAILURE == vmi_register_event(vmi, &interrupt_event) )
        goto done;

    SETUP_SINGLESTEP_EVENT(&singlestep_event, 1, singlestep_cb, 1);
    if ( VMI_FAILURE == vmi_register_event(vmi, &singlestep_event) )
        goto done;

    SETUP_MEM_EVENT(&mem_event, ~0ULL, VMI_MEMACCESS_RWX, mem_cb, 1);
    if ( VMI_FAILURE == vmi_register_event(vmi, &mem_event) )
        goto done;

    if ( VMI_OS_UNKNOWN == vmi_init_os(vmi, VMI_CONFIG_JSON_PATH, json, NULL) )
    {
        SETUP_REG_EVENT(&reg_event, CR3, VMI_REGACCESS_W, 0, cr3_cb);
        if ( VMI_FAILURE == vmi_register_event(vmi, &reg_event) )
        {
            printf("Failed to register CR3 event\n");
            goto done;
        }

        singlestep_event.callback = after_cr3_cb;

        vmi_resume_vm(vmi);

        while ( !interrupted && VMI_SUCCESS == vmi_events_listen(vmi, 500) )
        {}

        if ( interrupted != 1337 )
            goto done;

        vmi_clear_event(vmi, &reg_event, NULL);
        singlestep_event.callback = singlestep_cb;
        interrupted = 0;
    }

    if( VMI_OS_LINUX != vmi_get_ostype(vmi) )
    {
        printf("Only Linux is supported\n");
        goto done;
    }

    if ( VMI_FAILURE == vmi_translate_ksym2v(vmi, "dma_alloc_attrs", &dma_alloc_attrs) )
        goto done;

    printf("dma_alloc_attrs @ 0x%lx\n", dma_alloc_attrs);

    setup_handlers();

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
