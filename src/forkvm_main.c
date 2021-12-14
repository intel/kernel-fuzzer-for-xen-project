/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <stdlib.h>
#include "forkvm.h"

xc_interface *xc;
libxl_ctx *xl;
xc_dominfo_t info;
int vcpus;
uint32_t domid, forkdomid;

int main(int argc, char** argv)
{
    if ( argc < 2 )
    {
        printf("Usage: %s <domid> [reset]\n", argv[0]);
        return -1;
    }

    if ( !(xc = xc_interface_open(0, 0, 0)) )
        return -1;
    if ( libxl_ctx_alloc(&xl, LIBXL_VERSION, 0, NULL) )
        xl = NULL;

    domid = atoi(argv[1]);

    if ( 1 == xc_domain_getinfo(xc, domid, 1, &info) && info.domid == domid )
    {
        vcpus = ++info.max_vcpu_id;

        if ( fork_vm(domid, NULL, "forkvm", &forkdomid) )
            printf("Fork VM id: %u\n", forkdomid);
        else
            printf("Forking VM %u failed\n", domid);
    }

    if ( xl )
    {
        libxl_ctx_free(xl);
        xl = NULL;
    }
    xc_interface_close(xc);
    return 0;
}
