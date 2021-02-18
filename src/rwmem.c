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

    printf("Optional:\n");
    printf("\t --pagetable <address> (-1 for physical memory access)\n");
}

int main(int argc, char** argv)
{
    addr_t pagetable = 0;
    int c, long_index = 0;
    const struct option long_opts[] =
    {
        {"help", no_argument, NULL, 'h'},
        {"domid", required_argument, NULL, 'd'},
        {"read", required_argument, NULL, 'r'},
        {"write", required_argument, NULL, 'w'},
        {"limit", required_argument, NULL, 'L'},
        {"file", required_argument, NULL, 'f'},
        {"pagetable", required_argument, NULL, 'p'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "d:j:r:w:L:f:p:";
    bool read = false, write = false;
    size_t limit = 0;
    addr_t address = 0;
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
        case 'p':
            pagetable = strtoull(optarg, NULL, 0);
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
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = target_pagetable,
        .addr = address
    };

    if ( pagetable )
    {
        if ( pagetable == ~0ull )
        {
            ctx.translate_mechanism = VMI_TM_NONE;
            ctx.dtb = 0;
        }
        else
            ctx.dtb = pagetable;
    }

    size_t fsize = 0;
    FILE *i = fopen(filepath, read ? "w+" : "r");

    if (!i)
    {
        printf("Failed to open %s\n", filepath);
        goto done;
    }

    // Do large reads/writes in chunks
    unsigned int iters = limit < VMI_PS_4KB ? 1 : limit / VMI_PS_4KB;
    while ( iters-- )
    {
        unsigned long access_length;
        unsigned char buffer[VMI_PS_4KB] = {0};

        if ( !limit )
            break;
        if ( limit < VMI_PS_4KB )
        {
            access_length = limit;
            limit = 0;
        } else {
            access_length = VMI_PS_4KB;
            limit -= VMI_PS_4KB;
        }

        if ( read )
        {
            if ( VMI_SUCCESS == vmi_read(vmi, &ctx, access_length, (void*)&buffer, NULL) )
                printf("Read operation success: %lu bytes from 0x%lx\n", access_length, ctx.addr);
            else
                printf("Read operation failed from 0x%lx\n", ctx.addr);

            if ( 1 != fwrite(&buffer, access_length, 1, i) )
            {
                printf("Failed to save data in %s\n", filepath);
                break;
            }
        }

        if ( write )
        {
            if ( !(fsize = fread(&buffer, 1, access_length, i)) )
            {
                printf("Failed to read from %s\n", filepath);
                break;
            }

            if ( VMI_SUCCESS == vmi_write(vmi, &ctx, fsize, (void*)&buffer, NULL) )
                printf("Write operation success: %lu bytes to 0x%lx\n", fsize, ctx.addr);
            else
                printf("Write operation failed to 0x%lx\n", ctx.addr);

            if ( fsize < access_length )
            {
                printf("Nothing left in %s to read\n", filepath);
                break;
            }
        }

        ctx.addr += access_length;
    }

    fclose(i);

done:
    vmi_destroy(vmi);
    return 0;
}
