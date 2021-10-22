/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 *
 */
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <glib.h>

#include "vmi.h"
#include "save-transplant.h"

addr_t target_pagetable;
addr_t start_rip;
os_t os;
int interrupted;
page_mode_t pm;
vmi_instance_t vmi;

static void usage(void)
{
    printf("Usage:\n");
    printf("\t--domain <domain name>\n");
    printf("\t--domid <domain id>\n");
    printf("\t--memmap <memmap>\n");
    printf("\t--kvmi <socket>\n");
}

int main(int argc, char** argv)
{
    int c, long_index = 0;
    const struct option long_opts[] =
    {
        {"domain", required_argument, NULL, 'd'},
        {"domid", required_argument, NULL, 'i'},
        {"memmap", required_argument, NULL, 'm'},
        {"kvmi", required_argument, NULL, 'K'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "d:i:m:K:h";
    uint32_t domid = 0;
    char *domain = NULL;
    char *kvmi = NULL;
    const char *memmap = NULL;

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
        case 'm':
            memmap = optarg;
            break;
        case 'K':
            kvmi = optarg;
            break;
        case 'h': /* fall-through */
        default:
            usage();
            return -1;
        };
    }

    if ( (!domid && !domain) || !memmap )
    {
        usage();
        return -1;
    }

    if ( !setup_vmi(&vmi, domain, domid, NULL, kvmi, false, false) )
    {
        printf("Failed to init LibVMI\n");
        return -1;
    }

    vmi_pause_vm(vmi);

    if ( vmi_get_num_vcpus(vmi) > 1 )
    {
        printf("More then 1 vCPUs are not supported\n");
        goto done;
    }

    if ( !transplant_save_regs(vmi, "regs.csv") )
    {
        printf("Failed to save registers\n");
        goto done;
    }

    if ( !transplant_save_mem(vmi, memmap, "memmap", "vmcore") )
        printf("Failed to save memory\n");

done:
    vmi_resume_vm(vmi);
    vmi_destroy(vmi);

    return 0;
}
