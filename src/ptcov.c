/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <xenctrl.h>
#include <xen/xen.h>
#include <xenforeignmemory.h>
#include <glib.h>

#include <libvmi/libvmi.h>
#include <libxdc.h>

#include "afl.h"

extern xc_interface *xc;
extern uint32_t fuzzdomid;
extern bool debug;
extern reg_t target_pagetable;
extern vmi_instance_t vmi;
extern void *afl_area_ptr;

static uint8_t *pt_buf, *buf;
static void *bitmap;
static uint64_t pt_buf_size;

static xenforeignmemory_handle *fmem;
static xenforeignmemory_resource_handle *fres;

static libxdc_t* decoder;

static GHashTable *pages;

/* *************************************************************** */
static void* page_cache_fetch(void* self_ptr, uint64_t vaddr, bool* success)
{
    (void)self_ptr;
    uint64_t key;
    void *page;

    if ( VMI_FAILURE == vmi_pagetable_lookup(vmi, target_pagetable, vaddr, &key) )
    {
        *success = false;
        return NULL;
    }

    key >>= 12;

    if ( (page = g_hash_table_lookup(pages, &key)) )
    {
        *success = true;
        return page;
    }

    page = malloc(4096);

    if ( VMI_FAILURE == vmi_read_pa(vmi, key << 12, 4096, page, NULL) )
    {
        *success = false;
        free(page);
        return NULL;
    }

    g_hash_table_insert(pages, g_memdup(&key, sizeof(key)), page);

    *success = true;
    return page;
}

static void decode_cb(void* fd, uint64_t src, uint64_t dst)
{
    (void)fd;
    (void)src;

    if ( debug ) printf("[IPT] 0x%lx -> 0x%lx\n", src, dst);
}
/* *************************************************************** */

bool setup_pt(void)
{
    if ( !fuzzdomid )
        return false;

    if ( xc_vmtrace_pt_get_offset(xc, fuzzdomid, 0, NULL, &pt_buf_size) )
        return false;

    if ( xc_vmtrace_pt_set_option(xc, fuzzdomid, 0, XEN_DOMCTL_VMTRACE_PT_OS_EN, 1) )
        return false;

    if ( xc_vmtrace_pt_set_option(xc, fuzzdomid, 0, XEN_DOMCTL_VMTRACE_PT_DIS_RETC, 1) )
        return false;

    if ( xc_vmtrace_pt_enable(xc, fuzzdomid, 0) )
        return false;

    if ( !(fmem = xenforeignmemory_open(0, 0)) )
        return false;

    if ( !(buf = g_malloc0(pt_buf_size + 1)) )
        return false;

    if ( !afl_area_ptr && !(bitmap = g_malloc0(MAP_SIZE)) )
        return false;

    if ( !(pages = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free)) )
        return false;

    buf[pt_buf_size] = 0x55; // libxdc magic marker

    fres = xenforeignmemory_map_resource(
        fmem, fuzzdomid, XENMEM_resource_vmtrace_buf,
        0, 0, pt_buf_size >> XC_PAGE_SHIFT,
        (void **)&pt_buf,
        PROT_READ, 0);

    if ( !fres )
        return false;

    uint64_t filter[4][2] = { [0] = { 0x1000, ~0} };

    void *map = afl_area_ptr ?: bitmap;

    if ( !(decoder = libxdc_init(filter, &page_cache_fetch, NULL, map, MAP_SIZE)) )
        return false;

    if ( debug )
    {
        //libxdc_register_bb_callback(decoder, &decode_cb, NULL);

        libxdc_enable_tracing(decoder);
        int fd = open("/tmp/decoder_temp_trace_file", O_CREAT | O_TRUNC | O_WRONLY, S_IRWXU);
        libxdc_register_edge_callback(decoder, &decode_cb, &fd);
    }

    return true;
}

bool decode_pt(void)
{
    bool ret;
    size_t size;

    if ( xc_vmtrace_pt_get_offset(xc, fuzzdomid, 0, &size, NULL) )
        return false;

    memcpy(buf, pt_buf, size);

    if ( debug )
    {
        FILE *fp = fopen("buf", "w");
        fwrite(buf, size, 1, fp);
        fclose(fp);
    }

    buf[size] = 0x55;

    ret = 0 == libxdc_decode(decoder, buf, size);

    if ( bitmap )
        memset(bitmap, 0, MAP_SIZE);

    return ret;
}

bool close_pt(void)
{
    if ( !fuzzdomid )
        return true;

    if ( pages )
        g_hash_table_destroy(pages);
    if ( buf )
        g_free(buf);
    if ( bitmap )
        g_free(bitmap);
    if ( decoder )
    {
        libxdc_free(decoder);
        if ( debug )
            libxdc_disable_tracing(decoder);
    }
    if ( fres )
        xenforeignmemory_unmap_resource(fmem, fres);
    if ( fmem )
        xenforeignmemory_close(fmem);

    return 0 == xc_vmtrace_pt_disable(xc, fuzzdomid, 0);
}
