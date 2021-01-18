/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include <stdint.h>
#include <stdlib.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include "vmi.h"

vmi_instance_t vmi;
os_t os;
page_mode_t pm;
addr_t target_pagetable;
addr_t start_rip;
int interrupted;

static void usage(void)
{
    printf("Usage:\n");
    printf("\t --domid <domid>\n");
    printf("\t --read <address>\n");
    printf("\t --write <address>\n");
    printf("\t --file <input/output file>\n");
    printf("\t --limit <input/output limit>\n");
    printf("\t --npt <address>\n");
}

int main(int argc, char** argv)
{
    int c, long_index = 0;
    const struct option long_opts[] =
    {
        {"help", no_argument, NULL, 'h'},
        {"domid", required_argument, NULL, 'd'},
        {"read", required_argument, NULL, 'r'},
        {"write", required_argument, NULL, 'w'},
        {"limit", required_argument, NULL, 'L'},
        {"file", required_argument, NULL, 'f'},
        {"npt", required_argument, NULL, 'n'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "d:j:r:w:L:f:";
    bool read = false, write = false;
    size_t limit = 0;
    addr_t address = 0;
    addr_t npt = 0;
    char *filepath = NULL;
    uint32_t domid = 0;

    while ((c = getopt_long (argc, argv, opts, long_opts, &long_index)) != -1)
    {
        switch(c)
        {
        case 'd':
            domid = strtoul(optarg, NULL, 0);
            break;
        case 'r':
            read = true;
            address = strtoull(optarg, NULL, 0);
            break;
        case 'w':
            write = true;
            address = strtoull(optarg, NULL, 0);
            break;
        case 'L':
            limit = strtoull(optarg, NULL, 0);
            break;
        case 'f':
            filepath = optarg;
            break;
        case 'n':
            npt = strtoull(optarg, NULL, 0);
            break;
        case 'h': /* fall-through */
        default:
            usage();
            return -1;
        };
    }

    if ( !domid || (!read && !write) || (read && write) || !address || !limit || !filepath )
    {
        usage();
        return -1;
    }

    if ( !setup_vmi(&vmi, NULL, domid, NULL, false, true) )
        return -1;

    access_context_t ctx = {
        .version = ACCESS_CONTEXT_VERSION,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .addr = address,
        .dtb = target_pagetable
    };

    if ( npt )
    {
        ctx.npt = npt;
        ctx.npm = VMI_PM_EPT_4L;
    };

    size_t fsize = 0;
    FILE *i = NULL;
    unsigned char *buffer = malloc(limit);

    if ( !buffer )
        goto done;

    if ( read )
    {
        i = fopen(filepath,"w+");

        if ( i && VMI_SUCCESS == vmi_read(vmi, &ctx, limit, buffer, NULL) && 1 == fwrite(buffer, limit, 1, i) )
            printf("Read operation success: %lu bytes from 0x%lx\n", limit, address);
    }

    if ( write )
    {
        i = fopen(filepath,"r");

        if ( i && (fsize = fread(buffer, 1, limit, i)) && VMI_SUCCESS == vmi_write(vmi, &ctx, fsize, buffer, NULL) )
            printf("Write operation success: %lu bytes to 0x%lx\n", fsize, address);
    }

done:
    if ( i )
        fclose(i);

    free(buffer);
    vmi_destroy(vmi);

    return 0;
}
