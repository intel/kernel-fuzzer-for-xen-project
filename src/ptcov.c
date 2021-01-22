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

#include "private.h"

#define MSR_RTIT_CTL                        0x00000570
#define  RTIT_CTL_OS                        (1 <<  2)
#define  RTIT_CTL_USR                       (1 <<  3)
#define  RTIT_CTL_DIS_RETC                  (1 << 11)
#define  RTIT_CTL_BRANCH_EN                 (1 << 13)

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

static void record_cb(void* fd, uint64_t src, uint64_t dst)
{
    (void)fd;
    (void)src;
    g_hash_table_insert(codecov, GSIZE_TO_POINTER(dst), NULL);
}
/* *************************************************************** */

bool setup_pt(void)
{
    if ( !fuzzdomid )
        return false;

    xc_physinfo_t info;
    if ( xc_physinfo(xc, &info) )
        return false;

    if ( !(info.capabilities & XEN_SYSCTL_PHYSCAP_vmtrace) )
        return false;

    if ( !(fmem = xenforeignmemory_open(0, 0)) )
        return false;

    if ( xenforeignmemory_resource_size(fmem, fuzzdomid, XENMEM_resource_vmtrace_buf, 0, &pt_buf_size) )
    {
        fprintf(stderr, "ERROR: Unable to query vmtrace buffer size!\n");
        fprintf(stderr, "Make sure the domain config option for vmtrace is set and that you have a newer kernel!\n");
        return false;
    }

    if ( xc_vmtrace_set_option(
             xc, fuzzdomid, 0, MSR_RTIT_CTL,
             RTIT_CTL_BRANCH_EN | RTIT_CTL_USR | RTIT_CTL_OS | RTIT_CTL_DIS_RETC) )
        return false;

    if ( xc_vmtrace_enable(xc, fuzzdomid, 0) )
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

    if ( record_codecov )
        libxdc_register_bb_callback(decoder, &record_cb, NULL);

    if ( debug )
    {
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

    if ( xc_vmtrace_output_position(xc, fuzzdomid, 0, &size) )
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

    return 0 == xc_vmtrace_disable(xc, fuzzdomid, 0);
}
