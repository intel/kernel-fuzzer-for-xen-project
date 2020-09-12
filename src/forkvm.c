/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include <stdint.h>
#include <stdbool.h>

#include "forkvm.h"

extern int vcpus;
extern xc_interface *xc;

bool fork_vm(uint32_t domid, uint32_t *forkdomid)
{
    if ( !domid || !forkdomid )
        return false;

    struct xen_domctl_createdomain create = {0};
    create.flags |= XEN_DOMCTL_CDF_hvm;
    create.flags |= XEN_DOMCTL_CDF_hap;
    create.flags |= XEN_DOMCTL_CDF_oos_off;
    create.arch.emulation_flags = (XEN_X86_EMU_ALL & ~XEN_X86_EMU_VPCI);
    create.ssidref = 11; // SECINITSID_DOMU
    create.max_vcpus = vcpus;
    create.max_evtchn_port = 1023;
    create.max_grant_frames = LIBXL_MAX_GRANT_FRAMES_DEFAULT;
    create.max_maptrack_frames = LIBXL_MAX_MAPTRACK_FRAMES_DEFAULT;

    if ( xc_domain_create(xc, forkdomid, &create) )
        return false;

    if ( xc_memshr_fork(xc, domid, *forkdomid, true, true) )
    {
        xc_domain_destroy(xc, *forkdomid);
        return false;
    }

    return true;
}
