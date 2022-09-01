/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include <stdint.h>
#include <stdbool.h>

#include "forkvm.h"

extern int vcpus;
extern xc_interface *xc;
extern libxl_ctx *xl;
static char *ancestor_domname = NULL;
static uint32_t ancestor_domid = 0;

static bool rename_fork(uint32_t domid, char *sig, char *flavor, uint32_t forkdomid)
{
    char forkname[64];
    uint32_t dup_domid;
    if ( !xl )
        return false;
    if ( !ancestor_domname )
        /* Try to initialize it once */
        if ( !(ancestor_domname = libxl_domid_to_name(xl, domid)) )
            return false;
    if ( !ancestor_domid )
        ancestor_domid = domid;

    if ( sig )
        snprintf(forkname, sizeof(forkname), "%s-%d-%s-%s", ancestor_domname, ancestor_domid, flavor, sig);
    else
        snprintf(forkname, sizeof(forkname), "%s-%d-%s-%d", ancestor_domname, ancestor_domid, flavor, forkdomid);
    /* Check if this name is taken already because libxl can segfault if it is. */
    if ( !libxl_name_to_domid(xl, forkname, &dup_domid) )
        return false;
    return !libxl_domain_rename(xl, forkdomid, NULL, forkname);
}

bool fork_vm(uint32_t domid, char *fork_sig, char *fork_flavor, uint32_t *forkdomid)
{
    if ( !domid || !forkdomid )
        return false;

    struct xen_domctl_createdomain create = {0};
    create.flags |= XEN_DOMCTL_CDF_hvm;
    create.flags |= XEN_DOMCTL_CDF_hap;
    create.flags |= XEN_DOMCTL_CDF_oos_off;
    //create.flags |= XEN_DOMCTL_CDF_nested_virt; // nested virt ops not yet supported in forks
    create.arch.emulation_flags = (XEN_X86_EMU_ALL & ~XEN_X86_EMU_VPCI);
    create.ssidref = 11; // SECINITSID_DOMU
    create.max_vcpus = vcpus;
    create.max_evtchn_port = 1023;
    create.max_grant_frames = LIBXL_MAX_GRANT_FRAMES_DEFAULT;
    create.max_maptrack_frames = LIBXL_MAX_MAPTRACK_FRAMES_DEFAULT;
#if XEN_DOMCTL_INTERFACE_VERSION >= 0x00000014
    create.grant_opts = 2;
#endif

    if ( xc_domain_create(xc, forkdomid, &create) )
        return false;

    if ( xc_memshr_fork(xc, domid, *forkdomid, true, true) )
    {
        xc_domain_destroy(xc, *forkdomid);
        return false;
    }

    rename_fork(domid, fork_sig, fork_flavor, *forkdomid);

    return true;
}
