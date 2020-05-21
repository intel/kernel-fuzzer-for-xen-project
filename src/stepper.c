#include <stdint.h>
#include <stdlib.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <xenctrl.h>
#include <capstone.h>
#include "vmi.h"
#include "signal.h"

vmi_instance_t vmi;
os_t os;
addr_t target_pagetable;
addr_t start_rip;
bool loopmode;
int interrupted;
unsigned long limit, count;
xc_interface *xc;
csh cs_handle;

static void usage(void)
{
    printf("Usage:\n");
    printf("\t --domid <domid>\n");
    printf("\t --limit <singlestep count>\n");
    printf("\t --loopmode\n");
}

event_response_t tracer_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    unsigned char buf[15] = {0};
    cs_insn *insn = NULL;
    size_t read = 0, insn_count = 0;

    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = event->x86_regs->cr3,
        .addr = event->x86_regs->rip
    };

    vmi_read(vmi, &ctx, 15, buf, &read);

    if ( read )
        insn_count = cs_disasm(cs_handle, buf, read, event->x86_regs->rip, 0, &insn);

    printf("%lu: 0x%lx \t %s\n", ++count, event->x86_regs->rip, insn_count ? insn[0].mnemonic : "-");

    if ( count >= limit )
        interrupted = 1;

    if ( insn_count )
        cs_free(insn, insn_count);

    return 0;
}

int main(int argc, char** argv)
{
    int c, long_index = 0, rc;
    const struct option long_opts[] =
    {
        {"help", no_argument, NULL, 'h'},
        {"domid", required_argument, NULL, 'd'},
        {"limit", required_argument, NULL, 'L'},
        {"loopmode", no_argument, NULL, 'l'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "d:L:l";
    uint32_t domid;

    while ((c = getopt_long (argc, argv, opts, long_opts, &long_index)) != -1)
    {
        switch(c)
        {
        case 'd':
            domid = strtoul(optarg, NULL, 0);
            break;
        case 'L':
            limit = strtoull(optarg, NULL, 0);
            break;
        case 'l':
            loopmode = true;
            break;
        case 'h': /* fall-through */
        default:
            usage();
            return -1;
        };
    }

    if ( !domid || !limit )
    {
        usage();
        return -1;
    }

    if ( !setup_vmi(&vmi, NULL, domid, NULL, true, false) )
        return -1;

    if ( !(xc = xc_interface_open(0, 0, 0)) )
        goto done;

    if ( cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle) )
        goto done;

    setup_handlers();

    vmi_event_t singlestep_event;
    SETUP_SINGLESTEP_EVENT(&singlestep_event, 1, tracer_cb, 1);

    if ( VMI_SUCCESS != vmi_register_event(vmi, &singlestep_event) )
        goto done;

    do {
        vmi_resume_vm(vmi);
        while ( !interrupted && VMI_SUCCESS == vmi_events_listen(vmi, 500) )
        {}

        vmi_pause_vm(vmi);
        vmi_pagecache_flush(vmi);
        rc = xc_memshr_fork_reset(xc, domid);

        printf("----------------------------------------\n");
        interrupted = 0;
        count = 0;

        /*
         * Loopmode here is useful to check whether something causes divergence in the path
         * after a reset. There shouldn't be any divergence since after a reset the fork
         * should resume from the same state as before.
         */
    } while ( loopmode && !rc );

done:
    if ( xc )
        xc_interface_close(xc);
    cs_close(&cs_handle);
    vmi_clear_event(vmi, &singlestep_event, NULL);
    vmi_destroy(vmi);

    return 0;
}
