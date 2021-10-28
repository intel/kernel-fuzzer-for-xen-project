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
#include <glib/gprintf.h>
#include "vmi.h"
#include "signal.h"
#include "stack_unwind.h"
#include "save-transplant.h"
#include "city.h"

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
char *driver_filter;

bool stacktrace;

addr_t kfx_dma_log, kfx_dma_log_cc;
addr_t dma_alloc_attrs, dma_alloc_attrs_ret;
uint8_t dma_alloc_attrs_ret_backup;

size_t alloc_size;
addr_t alloc_dev;
char* alloc_dev_name;
bool alloc_only;

uint8_t cc = 0xCC, ret = 0xC3, nop = 0x90;
vmi_event_t interrupt_event;
vmi_event_t mem_event;
vmi_event_t singlestep_event;
vmi_event_t reg_event;
emul_insn_t emul_insn = { .dont_free = 1 };

addr_t device_driver_offset = 0, driver_name_offset = 0;

GHashTable *dma_tracker;
GHashTable *stack_tracker;

const char *memmap;

uint64_t stack_save_key, stack_frames;
char *stack_unique;

static void options(void)
{
    printf("Options:\n");
    printf("\t--domain <domain name>\n");
    printf("\t--domid <domain id>\n");
    printf("\t--json <path to kernel debug json>\n");
    printf("\t--driver <driver/module name>\n");
    printf("\t--dma <dma address>\n");
    printf("\t--alloc-only\n");
    printf("\t--stacktrace\n");
    printf("\t--wait-for-cr3\n");
    printf("\t--memmap <memmap> (if specified will save a snapshot for unique stacktraces)\n");
    printf("\t--stack-save-key <key> (specify to save snapshot only for specific stacktrace)\n");
    printf("\t--stack-frames <# of frames> (specify to limit stack key calculation)\n");
    printf("\t--stack-save-unique <file> (save unique stacks to file)\n");
    printf("\t--kvmi <socket>\n");
}

static void set_dma_permissions(vmi_instance_t vmi, addr_t dma, addr_t cr3, vmi_mem_access_t access)
{
    if ( cr3 )
    {
        addr_t gfn = 0;
        if ( VMI_FAILURE == vmi_pagetable_lookup(vmi, cr3, dma, &gfn) )
            return;

        dma = gfn >> 12;
    } else
        dma >>= 12;

    gpointer key = GSIZE_TO_POINTER(dma);
    unsigned int counter = GPOINTER_TO_UINT(g_hash_table_lookup(dma_tracker, key));

    if ( access == VMI_MEMACCESS_N )
    {
        if ( !counter )
            return;

        counter--;

        if ( !counter )
        {
            if ( VMI_FAILURE == vmi_set_mem_event(vmi, dma, access, 0) )
                return;

            printf("EPT permissions relaxed for page at 0x%lx\n", dma);

            g_hash_table_remove(dma_tracker, key);
        } else
            g_hash_table_insert(dma_tracker, key, GUINT_TO_POINTER(counter));

    } else {
        counter++;

        if ( counter == 1 )
        {
            if ( VMI_FAILURE == vmi_set_mem_event(vmi, dma, access, 0) )
                return;

            printf("EPT permissions restricted for page at 0x%lx\n", dma);
        }

        g_hash_table_insert(dma_tracker, key, GUINT_TO_POINTER(counter));
    }
}

static void reset_dma_permissions(gpointer data)
{
    addr_t dma = GPOINTER_TO_SIZE(data);
    if ( VMI_SUCCESS == vmi_set_mem_event(vmi, dma, VMI_MEMACCESS_N, 0) )
        printf("EPT permissions relaxed for page at 0x%lx\n", dma);
}

static event_response_t singlestep_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    vmi_set_mem_event(vmi, GPOINTER_TO_SIZE(event->data), VMI_MEMACCESS_RW, 0);
    return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
}

/*
 * Assume kernel is built with CONFIG_FRAME_POINTER
 */
static void do_stacktrace(vmi_instance_t vmi, vmi_event_t *event, addr_t memaccess)
{
#ifndef HAVE_XEN
    /*
     * On KVM the memory access is 1-copy instead of zero-copy, so need to make sure
     * all pages are fresh before poking around.
     */
    vmi_pagecache_flush(vmi);
#endif

    uint64_t key = 0, counter = 0;
    GSList *stack = stack_unwind(vmi, event->x86_regs, event->page_mode);
    GSList *loop = stack;

    while(loop)
    {
        addr_t ip = GPOINTER_TO_SIZE(loop->data);
        loop = loop->next;
        counter++;

        printf("\t0x%lx\n", ip);

        // calculate stack key up to limit specified (0 = no limit)
        if ( !stack_frames || stack_frames >= counter )
            key = Hash128to64(key, ip);
    }

    gpointer found = g_hash_table_lookup(stack_tracker, GSIZE_TO_POINTER(key));

    printf("\tStack key: 0x%lx %s\n", key, found ? "" : "new!");

    if ( !found )
    {
        g_hash_table_insert(stack_tracker, GSIZE_TO_POINTER(key), GSIZE_TO_POINTER(1));

        FILE *f = NULL;

        if ( stack_unique && (f = fopen(stack_unique, "a")) )
        {
            fprintf(f, "-- key: 0x%lx --\n", key);

            loop = stack;
            while(loop)
            {
                fprintf(f, "0x%lx\n", GPOINTER_TO_SIZE(loop->data));
                loop = loop->next;
            }

            fclose(f);
            f = NULL;
        }

        if ( memmap && (!stack_save_key || stack_save_key == key) )
        {
            gchar *regf = g_strdup_printf("regs-0x%lx.csv", key);
            gchar *mapf = g_strdup_printf("memmap-0x%lx", key);
            gchar *vmcoref = g_strdup_printf("vmcore-0x%lx", key);
            gchar *maccessf = g_strdup_printf("memaccess-0x%lx", key);
            gchar *stackf = g_strdup_printf("stacktrace-0x%lx", key);
            gchar *tar = g_strdup_printf("tar --remove-files -czf snapshot-0x%lx.tar.gz regs-0x%lx.csv memmap-0x%lx vmcore-0x%lx memaccess-0x%lx stacktrace-0x%lx",
                                         key, key, key, key, key, key);

            // don't save the kfx log breakpoint in the snapshot
            vmi_write_8_va(vmi, kfx_dma_log_cc, 0, &nop);

            transplant_save_regs(vmi, regf);
            transplant_save_mem(vmi, memmap, mapf, vmcoref);

            // add back the breakpoint
            vmi_write_8_va(vmi, kfx_dma_log_cc, 0, &cc);

            f = fopen(maccessf, "w");
            if ( f )
            {
                fprintf(f, "0x%lx\n", memaccess);
                fclose(f);
            };

            f = fopen(stackf, "w");
            if ( f )
            {
                loop = stack;
                while(loop)
                {
                    addr_t ip = GPOINTER_TO_SIZE(loop->data);
                    loop = loop->next;
                    fprintf(f, "0x%lx\n", ip);
                }
                fclose(f);
            }

            printf("Compressing: %s\n", tar);

            g_spawn_command_line_async(tar, NULL);

            g_free(tar);
            g_free(stackf);
            g_free(maccessf);
            g_free(regf);
            g_free(mapf);
            g_free(vmcoref);
        }
    }

    g_slist_free(stack);
}

static event_response_t mem_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    printf("DMA access! RIP: 0x%lx Mem: 0x%lx %c%c\n",
           event->x86_regs->rip, event->mem_event.gla,
           (event->mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
           (event->mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-');

    if ( (event->mem_event.out_access & VMI_MEMACCESS_R) && (stacktrace || memmap) )
        do_stacktrace(vmi, event, event->mem_event.gla);

    vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_N, 0);
    singlestep_event.data = GSIZE_TO_POINTER(event->mem_event.gfn);
    return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
}

/*
 * If kfx_dma_log is defined for the kernel we track that. It's a custom function
 * that can be compiled into the kernel at desired locations that is easier to hook
 * to collect all the necessary info to track DMA usage.
 *
 * Otherwise we breakpoint dma_alloc_attrs to catch all callers, then breakpoint
 * the return site. At the return site we extract the returned DMA address
 * and remove the underlying EPT permission. This approach is more fragile
 * and may miss and also overmonitor pages as we don't track when pages are no
 * longer used for DMA (ie. dma_free_attrs) or when DMA is setup using other
 * APIs or the swiotlb.
 *
 */
static event_response_t int3_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    event->interrupt_event.reinject = 0;

    if ( event->x86_regs->rax == 0x13371337 )
    {
        /*
         * We might find sink breakpoints, ignore those.
         */
        event->x86_regs->rip += 1;
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }
    else if ( event->x86_regs->rax == 0x13371338 )
    {
        /*
         * Found the custom kfx_dma_log function.
         * See patches/0001-kfx_dma_log-virtio-snapshotting.patch
         */

        kfx_dma_log_cc = event->interrupt_event.gla;

        addr_t vaddr = event->x86_regs->rdi;
        addr_t paddr = event->x86_regs->rsi;
        addr_t dmaaddr = event->x86_regs->rdx;
        unsigned long size = event->x86_regs->rcx;
        addr_t dev = event->x86_regs->r8;
        bool map = event->x86_regs->r9;

        bool ignore_alloc = false;
        addr_t dev_driver, driver_name;

        if ( (VMI_FAILURE != vmi_read_addr_va(vmi, dev + device_driver_offset, 0, &dev_driver)) &&
             (VMI_FAILURE != vmi_read_addr_va(vmi, dev_driver + driver_name_offset, 0, &driver_name)) &&
             (NULL == (alloc_dev_name = vmi_read_str_va(vmi, driver_name, 0))) )
            printf("Failed to read driver name\n");

        if ( driver_filter )
        {
            if ( !alloc_dev_name )
                ignore_alloc = true;
            else if ( strcmp(driver_filter, alloc_dev_name) )
                ignore_alloc = true;
        }

        printf("KF/x DMA log %s: 0x%lx -> 0x%lx <- DMA -> 0x%lx, size: %lu, map: %i\n", alloc_dev_name, vaddr, paddr, dmaaddr, size, map);

        if ( alloc_dev_name )
        {
            free(alloc_dev_name);
            alloc_dev_name = NULL;
        }

        if ( !alloc_only && !ignore_alloc )
        {
            ACCESS_CONTEXT(ctx);
            ctx.tm = VMI_TM_PROCESS_DTB;
            ctx.addr = event->x86_regs->rip;
            ctx.pt = event->x86_regs->cr3;
            ctx.pm = event->page_mode;

            addr_t start = vaddr ?: paddr;
            addr_t pt = vaddr ? event->x86_regs->cr3 : 0;
            vmi_mem_access_t access = map ? VMI_MEMACCESS_RW : VMI_MEMACCESS_N;

            // Make sure all pages underlying the allocation request are monitored
            size += start & VMI_BIT_MASK(0,11);
            unsigned int pages = size / 0x1000 + !!(size % 0x1000);

            for ( size_t i = 0; i < pages; i+=0x1000 )
                 set_dma_permissions(vmi, start + i, pt, access);

            event->x86_regs->rip += 1;
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
    }
#ifdef HAVE_XEN
    else if ( event->interrupt_event.gla == dma_alloc_attrs )
    {
        bool ignore_alloc = false;
        addr_t dev_driver, driver_name;
        addr_t tmp = 0;

        ACCESS_CONTEXT(ctx);
        ctx.tm = VMI_TM_PROCESS_DTB;
        ctx.addr = event->x86_regs->rsp;
        ctx.pt = event->x86_regs->cr3;
        ctx.pm = event->page_mode;

        if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &tmp) )
            printf("Reading stack return failed\n");

        if ( dma_alloc_attrs_ret && dma_alloc_attrs_ret != tmp )
        {
            vmi_write_8_va(vmi, dma_alloc_attrs_ret, 0, &dma_alloc_attrs_ret_backup);
        }

        alloc_dev = event->x86_regs->rdi;
        alloc_size = event->x86_regs->rsi;

        if ( alloc_dev_name )
        {
            free(alloc_dev_name);
            alloc_dev_name = NULL;
        }

        if ( (VMI_FAILURE != vmi_read_addr_va(vmi, alloc_dev + device_driver_offset, 0, &dev_driver)) &&
             (VMI_FAILURE != vmi_read_addr_va(vmi, dev_driver + driver_name_offset, 0, &driver_name)) &&
             (NULL == (alloc_dev_name = vmi_read_str_va(vmi, driver_name, 0))) )
            printf("Failed to read driver name\n");

        if ( driver_filter )
        {
            if ( !alloc_dev_name )
                ignore_alloc = true;
            else if ( strcmp(driver_filter, alloc_dev_name) )
                ignore_alloc = true;
        }

        if ( tmp )
        {
            if ( !ignore_alloc )
            {
                dma_alloc_attrs_ret = tmp;
                vmi_read_8_va(vmi, dma_alloc_attrs_ret, 0, &dma_alloc_attrs_ret_backup);
                vmi_write_8_va(vmi, dma_alloc_attrs_ret, 0, &cc);
            }

            event->emul_insn = &emul_insn;
        }

        return VMI_EVENT_RESPONSE_EMULATE | VMI_EVENT_RESPONSE_SET_EMUL_INSN;
    }
    else if ( event->interrupt_event.gla == dma_alloc_attrs_ret )
    {
        target_pagetable = event->x86_regs->cr3;
        vmi_write_8_va(vmi, dma_alloc_attrs_ret, 0, &dma_alloc_attrs_ret_backup);
        dma_alloc_attrs_ret_backup = 0;
        dma_alloc_attrs_ret = 0;

        printf("DMA allocated @ 0x%lx. Size: %lu. Dev: %s @ 0x%lx\n", event->x86_regs->rax, alloc_size, alloc_dev_name, alloc_dev);

        if ( alloc_dev_name )
        {
            free(alloc_dev_name);
            alloc_dev_name = NULL;
        }

        if ( !alloc_only )
        {
            addr_t start = event->x86_regs->rax;
            alloc_size += start & VMI_BIT_MASK(0,11);
            unsigned int pages = alloc_size / 0x1000 + (alloc_size % 0x1000 ? 1 : 0);

            for ( size_t i = 0; i < pages; i+=0x1000 )
                 set_dma_permissions(vmi, start + i, target_pagetable, VMI_MEMACCESS_RW);
        }
    }
#endif
    else
        event->interrupt_event.reinject = 1;

    return 0;
}

static event_response_t after_cr3_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    event_response_t rc = VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;

    printf("Got CR3 callback, trying to init LibVMI OS bits\n");

    if ( VMI_PM_UNKNOWN == vmi_init_paging(vmi, event->vcpu_id) )
        return rc;

    if ( VMI_OS_UNKNOWN == vmi_init_os(vmi, VMI_CONFIG_JSON_PATH, json, NULL) )
        return rc;

    printf("LibVMI OS init success\n");

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
        {"driver", required_argument, NULL, 'r'},
        {"stacktrace", no_argument, NULL, 's'},
        {"alloc-only", no_argument, NULL, 'o'},
        {"wait-for-cr3", no_argument, NULL, 'w'},
        {"memmap", required_argument, NULL, 'm'},
        {"stack-save-key", required_argument, NULL, 'k'},
        {"stack-frames", required_argument, NULL, 'F'},
        {"stack-save-unique", required_argument, NULL, 'U'},
        {"kvmi", required_argument, NULL, 'K'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "d:i:j:a:r:m:k:S:K:sowh";
    uint32_t domid = 0;
    char *domain = NULL;
    char *kvmi = NULL;
    bool wait_for_cr3 = false;
    GSList *dma_list = NULL;

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
        case 'r':
        {
            driver_filter = optarg;
            break;
        }
        case 'o':
            alloc_only = 1;
            break;
        case 'w':
            wait_for_cr3 = true;
            break;
        case 'm':
            memmap = optarg;
            break;
        case 'k':
            stack_save_key = strtoull(optarg, NULL, 0);
            break;
        case 'F':
            stack_frames = strtoull(optarg, NULL, 0);
            break;
        case 'U':
            stack_unique = optarg;
            break;
        case 'K':
            kvmi = optarg;
            break;
        case 'h': /* fall-through */
        default:
            options();
            return -1;
        };
    }

    if ( (!domid && !domain) || !json )
    {
        options();
        return -1;
    }

    setup_handlers();

    if ( !setup_vmi(&vmi, domain, domid, NULL, kvmi, true, false) )
    {
        printf("Failed to enable LibVMI\n");
        return -1;
    }

    vmi_pause_vm(vmi);

    dma_tracker = g_hash_table_new_full(g_direct_hash, g_direct_equal, reset_dma_permissions, NULL);
    stack_tracker = g_hash_table_new(g_direct_hash, g_direct_equal);

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

    if ( wait_for_cr3 || VMI_OS_UNKNOWN == vmi_init_os(vmi, VMI_CONFIG_JSON_PATH, json, NULL) )
    {
        printf("Registering CR3 callback\n");

        SETUP_REG_EVENT(&reg_event, CR3, VMI_REGACCESS_W, 0, cr3_cb);
        if ( VMI_FAILURE == vmi_register_event(vmi, &reg_event) )
        {
            printf("Failed to register CR3 event\n");
            goto done;
        }

        singlestep_event.callback = after_cr3_cb;

        printf("Waiting for CR3 callback\n");

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

    if ( VMI_SUCCESS == vmi_translate_ksym2v(vmi, "kfx_dma_log", &kfx_dma_log) )
        printf("kfx_dma_log @ 0x%lx\n", kfx_dma_log);
#ifdef HAVE_XEN
    else {
        if ( VMI_FAILURE == vmi_translate_ksym2v(vmi, "dma_alloc_attrs", &dma_alloc_attrs) )
            goto done;
        if ( VMI_FAILURE == vmi_read_va(vmi, dma_alloc_attrs, 0, 15, &emul_insn.data, NULL) )
            goto done;
        if ( VMI_FAILURE == vmi_write_8_va(vmi, dma_alloc_attrs, 0, &cc) )
            goto done;

        printf("dma_alloc_attrs @ 0x%lx\n", dma_alloc_attrs);
    }
#else
    else {
        printf("On KVM the target kernel must be compiled with kfx_dma_log\n");
        goto done;
    }
#endif

    if ( (VMI_FAILURE == vmi_get_kernel_struct_offset(vmi, "device", "driver", &device_driver_offset)) ||
         (VMI_FAILURE == vmi_get_kernel_struct_offset(vmi, "device_driver", "name", &driver_name_offset)) )
    {
        fprintf(stderr, "Cannot find device driver name offsets\n");
        goto done;
    }

    GSList *tmp = dma_list;
    while ( tmp )
    {
        addr_t dma = GPOINTER_TO_SIZE(tmp->data);
        set_dma_permissions(vmi, dma, target_pagetable, VMI_MEMACCESS_RW);

        tmp = tmp->next;
    }

    if ( dma_list )
        g_slist_free(dma_list);

    if ( stacktrace || memmap )
        stack_unwind_init();

    vmi_resume_vm(vmi);

    while ( !interrupted && VMI_SUCCESS == vmi_events_listen(vmi, 500) )
    {}

done:
    if ( dma_alloc_attrs )
        vmi_write_8_va(vmi, dma_alloc_attrs, 0, (uint8_t*)&emul_insn.data);
    if ( alloc_dev_name )
        free(alloc_dev_name);

    if ( stacktrace || memmap )
        stack_unwind_clear();

    g_hash_table_destroy(dma_tracker);
    g_hash_table_destroy(stack_tracker);

    vmi_resume_vm(vmi);
    vmi_destroy(vmi);

    return 0;
}
