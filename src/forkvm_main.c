/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <stdlib.h>
#include "forkvm.h"

xc_interface *xc;
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

    domid = atoi(argv[1]);

    if ( 1 == xc_domain_getinfo(xc, domid, 1, &info) && info.domid == domid )
    {
        vcpus = ++info.max_vcpu_id;

        if ( fork_vm(domid, &forkdomid) )
            printf("Fork VM id: %u\n", forkdomid);
        else
            printf("Forking VM %u failed\n", domid);
    }

    xc_interface_close(xc);
    return 0;
}
