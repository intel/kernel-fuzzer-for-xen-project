/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include "private.h"

static void get_input(void)
{
    if ( !input_limit )
        return;

    if ( debug ) printf("Get %lu bytes of input from %s\n", input_limit, input_path);

    input_file = fopen(input_path, "r");
    if (!input_file){
        return;
    }

    input = malloc(input_limit);
    if ( !input ){
        fclose(input_file);
        input_file = NULL;
        return;
    }

    if ( !(input_size = fread(input, 1, input_limit, input_file)) )
    {
        free(input);
        input = NULL;
    }
    fclose(input_file);
    input_file = NULL;

    if ( debug ) printf("Got input size %lu\n", input_size);
}

static bool inject_input(vmi_instance_t vmi)
{
    if ( !input || !input_size )
        return false;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .pt = target_pagetable,
        .addr = address
    );

    if ( debug ) printf("Writing %lu bytes of input to 0x%lx\n", input_size, address);

    return VMI_SUCCESS == vmi_write(vmi, &ctx, input_size, input, NULL);
}

static bool make_fuzz_ready()
{
    if ( !fuzzdomid )
        return false;

    if ( !setup_vmi(&vmi, NULL, fuzzdomid, json, NULL, true, true) )
    {
        fprintf(stderr, "Unable to start VMI on fuzz domain %u\n", fuzzdomid);
        return false;
    }

    if ( ptcov && !setup_pt() )
    {
        fprintf(stderr, "Failed to enable Processor Tracing\n");
        return false;
    }

    setup_trace(vmi);

    if ( debug ) printf("VM Fork is ready for fuzzing\n");

    return true;
}

static bool fuzz(void)
{
    if ( !fuzzdomid )
        return false;

    if ( xc_memshr_fork_reset(xc, fuzzdomid) )
        return false;

    crash = 0;

    if ( afl )
    {
        afl_rewind();
        afl_instrument_location(start_rip);
        afl_wait();
    }

    get_input();

    if ( !start_trace(vmi, start_rip) )
        return false;
    if ( !inject_input(vmi) )
    {
        fprintf(stderr, "Injecting input failed\n");
        return false;
    }

    if ( debug ) printf("Starting fuzz loop\n");
    loop(vmi);
    if ( debug ) printf("Stopping fuzz loop.\n");

    if ( ptcov )
        decode_pt();

    vmi_pagecache_flush(vmi);
    vmi_v2pcache_flush(vmi, target_pagetable);
    vmi_pidcache_flush(vmi);
    vmi_rvacache_flush(vmi);
    vmi_symcache_flush(vmi);

    bool ret = false;

    if ( afl )
    {
        afl_report(crash);
        ret = true;
    }
    else if ( loopmode )
    {
        if ( crash )
        {
            FILE *f = fopen("crash.out","w+");
            fwrite(input, input_size, 1, f);
            fclose(f);
            ret = false;
        } else
            ret = true;
    } else
        printf("Result: %s\n", crash ? "crash" : "no crash");

    free(input);
    input = NULL;

    return ret;
}

static bool validate_flags()
{
    if ( !domain && !domid )
    {
        fprintf(stderr, "Must specify --domain OR --domid of parent VM\n");
        return false;
    }
    if ( !setup && ((!address == !extended_mark) || (!input_limit == !extended_mark)) )
    {
        fprintf(stderr, "Must exclusively specify either (--address AND --input-limit) of target buffer OR --extended-mark\n");
        return false;
    }
    if ( !setup && !input_path )
    {
        fprintf(stderr, "Must specify --input path of taget buffer\n");
        return false;
    }
    if ( !setup && !json && !sink_list )
    {
        fprintf(stderr, "Must specify either kernel sym --json OR --sink-vaddr/--sink-paddr per sink\n");
        return false;
    }
    return true;
}

static void usage(void)
{
    printf("Inputs required for SETUP step:\n");
    printf("\t  -s  --setup\n");
    printf("\t  -d  --domain <domain name> OR -i  --domid <domain id>\n");
    printf("\tOptional inputs:\n");
    printf("\t  -H  --harness cpuid|breakpoint (default is cpuid)\n");
    printf("\t  -m  --magic-mark <magic number signaling start harness> (default is 0x13371337)\n");
    printf("\t  -c  --extended-mark (Use start harness to obtain target address & size)\n");
    printf("\t  -S  --start-byte <byte> (used to replace the starting breakpoint harness)\n");

    printf("\n\n");
    printf("Inputs required for FUZZING step:\n");
    printf("\t  -f  --input <path to input file> or @@ with AFL\n");
    printf("\t  -L  --input-limit <limit input size> (XOR --extended-mark)\n");
    printf("\t  -a  --address <kernel virtual address to inject input to> (XOR --extended-mark)\n");
    printf("\t  -d  --domain <domain name> OR -i, --domid <domain id>\n");
    printf("\t  -j  --json <path to kernel debug json> (needed only if default sink list is used or --sink is used)\n");
    printf("\tOptional inputs:\n");
    printf("\t  -c  --extended-mark (Use start harness to obtain target address & size)\n");
    printf("\t  -f  --limit <limit FUZZING execution to # of CF instructions>\n");
    printf("\t  -H  --harness cpuid|breakpoint (default is cpuid)\n");
    printf("\t  -O  --loopmode (Run in a loop without coverage trace, for example using /dev/urandom as input)\n");
    printf("\t  -r  --refork <create new fork after # of executions>\n");
    printf("\t  -K  --keep (keep VM fork after kfx exits)\n");
    printf("\t  -N  --nocov (disable coverage tracing)\n");
    printf("\t  -t  --ptcov (use IPT coverage tracing)\n");
    printf("\t  -D  --detect-doublefetch <kernel virtual address on page to detect doublefetch>\n");
    printf("\t  -n  --sink <function_name>\n");
    printf("\t  -V  --sink-vaddr <virtual address>\n");
    printf("\t  -P  --sink-paddr <physical address>\n");
    printf("\t  -R  --record-codecov <path to save file>\n");

    printf("\n\n");
    printf("Optional global inputs:\n");
    printf("\t-v, --debug\n");
    printf("\t-F, --logfile <path to logfile>\n");
}

int main(int argc, char** argv)
{
    char *logfile = NULL;
    int c, out = 0, long_index = 0;
    const struct option long_opts[] =
    {
        {"help", no_argument, NULL, 'h'},
        {"domain", required_argument, NULL, 'd'},
        {"domid", required_argument, NULL, 'i'},
        {"json", required_argument, NULL, 'j'},
        {"input", required_argument, NULL, 'f'},
        {"input-limit", required_argument, NULL, 'L'},
        {"address", required_argument, NULL, 'a'},
        {"limit", required_argument, NULL, 'l'},
        {"setup", no_argument, NULL, 's'},
        {"debug", no_argument, NULL, 'v'},
        {"logfile", required_argument, NULL, 'F'},
        {"harness", required_argument, NULL, 'H'},
        {"start-byte", required_argument, NULL, 'S'},
        {"refork", required_argument, NULL, 'r'},
        {"loopmode", no_argument, NULL, 'O'},
        {"keep", no_argument, NULL, 'K'},
        {"nocov", no_argument, NULL, 'N'},
        {"ptcov", no_argument, NULL, 't'},
        {"detect-doublefetch", required_argument, NULL, 'D'},
        {"magic-mark", required_argument, NULL, 'm'},
        {"extended-mark", no_argument, NULL, 'c'},
        {"sink", required_argument, NULL, 'n'},
        {"sink-vaddr", required_argument, NULL, 'V'},
        {"sink-paddr", required_argument, NULL, 'P'},
        {"record-codecov", required_argument, NULL, 'R'},
        {"record-memaccess", required_argument, NULL, 'M'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "d:i:j:f:a:l:F:H:S:m:n:V:P:R:M:svchtOKND";
    limit = ~0;
    unsigned long refork = 0;
    bool keep = false;
    bool default_magic_mark = true;

    address = 0;
    magic_mark = 0;
    harness_cpuid = true;
    input_path = NULL;
    input_size = 0;
    input_limit = 0;

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
        case 'j':
            json = optarg;
            break;
        case 'f':
            input_path = optarg;
            break;
        case 'a':
            address = strtoull(optarg, NULL, 0);
            break;
        case 'l':
            limit = strtoull(optarg, NULL, 0);
            break;
        case 'L':
            input_limit = strtoull(optarg, NULL, 0);
            break;
        case 's':
            setup = true;
            break;
        case 'v':
            debug = true;
            break;
        case 'F':
            logfile = optarg;
            break;
        case 'H':
            if ( !strcmp(optarg, "breakpoint") )
                harness_cpuid = false;
            break;
        case 'S':
            start_byte = strtoull(optarg, NULL, 0);
            break;
        case 'r':
            refork = strtoull(optarg, NULL, 0);
            break;
        case 'O':
            loopmode = true;
            nocov = true;
            break;
        case 'K':
            keep = true;
            break;
        case 'N':
            nocov = true;
            break;
        case 't':
            ptcov = true;
            break;
        case 'D':
            doublefetch = g_slist_prepend(doublefetch, GSIZE_TO_POINTER(strtoull(optarg, NULL, 0)));
            break;
        case 'm':
            default_magic_mark = false;
            magic_mark = strtoul(optarg, NULL, 0);
            break;
        case 'c':
            extended_mark = true;
            break;
        case 'n':
        {
            struct sink *s = g_malloc0(sizeof(struct sink));
            s->function = optarg;
            sink_list = g_slist_prepend(sink_list, s);
            break;
        }
        case 'V':
        {
            struct sink *s = g_malloc0(sizeof(struct sink));
            s->vaddr = strtoull(optarg, NULL, 0);
            sink_list = g_slist_prepend(sink_list, s);
            break;
        }
        case 'P':
        {
            struct sink *s = g_malloc0(sizeof(struct sink));
            s->paddr = strtoull(optarg, NULL, 0);
            sink_list = g_slist_prepend(sink_list, s);
            break;
        }
        case 'R':
            record_codecov = optarg;
            break;
        case 'M':
            record_memaccess = optarg;
            break;
        case 'h': /* fall-through */
        default:
            usage();
            return -1;
        };
    }

    if ( !validate_flags() )
    {
        usage();
        return -1;
    }

    if ( !harness_cpuid )
    {
        if ( !start_byte )
        {
            printf("For breakpoint harness --start-byte with a value must be provided (NOP is always a good option, 0x90)\n");
            return -1;
        }

        if ( default_magic_mark )
            magic_mark = 0;
    } else if ( default_magic_mark && setup )
        magic_mark = 0x13371337;


    if ( logfile )
    {
        out = open(logfile, O_RDWR|O_CREAT|O_APPEND, 0600);
        if (-1 == dup2(out, fileno(stdout))) { close(out); return -1; }
        if (-1 == dup2(out, fileno(stderr))) { close(out); return -1; }
    }

    if ( debug ) printf ("############ START ################\n");

    setup_handlers();

    bool parent_ready = make_parent_ready();

    if ( setup )
    {
        if ( logfile ) close(out);
        return parent_ready ? 0 : -1;
    }

    if ( !parent_ready )
        goto done;

    if ( !(xc = xc_interface_open(0, 0, 0)) )
    {
        fprintf(stderr, "Failed to grab xc interface\n");
        goto done;
    }

    /*
     * To reduce the churn of placing the sink breakpoints into the VM fork's memory
     * for each fuzzing iteration (which requires full-page copies for each breakpoint)
     * we create a fork that will only be used to house the breakpointed sinks,
     * ie. sinkdomid. We don't want to place the breakpoints in the parent VM
     * since that would prohibit other kfx instances from running on the domain
     * with potentially other sinkpoints.
     *
     * Fuzzing is performed from a further fork made from sinkdomid, in fuzzdomid.
     */
    if ( !fork_vm(domid, &sinkdomid) )
    {
        fprintf(stderr, "Domain fork failed, sink domain not up\n");
        goto done;
    }

    if ( !fork_vm(sinkdomid, &fuzzdomid) )
    {
        fprintf(stderr, "Domain fork failed, fuzz domain not up\n");
        goto done;
    }

    afl_setup();

    if ( !afl )
    {
        input_file = fopen(input_path,"r"); // Sanity check
        if ( !input_file )
        {
            fprintf(stderr, "Failed to open input file %s\n", input_path);
            goto done;
        }
        fclose(input_file); // Closing for now, will reopen when needed

        printf("Fork VMs created: %u -> %u -> %u\n", domid, sinkdomid, fuzzdomid);
    }

    input_file = NULL;

    if ( !make_sink_ready() )
    {
        fprintf(stderr, "Seting up sinks on VM fork domid %u failed\n", sinkdomid);
        goto done;
    }

    if ( !nocov && !ptcov && cs_open(CS_ARCH_X86, pm == VMI_PM_IA32E ? CS_MODE_64 : CS_MODE_32, &cs_handle) )
    {
        fprintf(stderr, "Capstone init failed\n");
        goto done;
    }

    if ( !make_fuzz_ready() )
    {
        fprintf(stderr, "Seting up fuzzing on VM fork domid %u failed\n", fuzzdomid);
        goto done;
    }

    if ( debug ) printf("Starting fuzzer on %u\n", fuzzdomid);

    if ( loopmode ) printf("Running in loopmode\n");
    else if ( afl )  printf("Running in AFL mode\n");
    else printf("Running in standalone mode\n");

    unsigned long iter = 0, t = time(0), cycle = 0;

    while ( fuzz() )
    {
        iter++;

        if ( loopmode )
        {
            unsigned long now = time(0);
            if (t != now)
            {
                printf("Completed %lu iterations\n", iter - cycle);
                t = now;
                cycle = iter;
            }
        }

        if ( iter == refork )
        {
            close_trace(vmi);
            vmi_destroy(vmi);
            xc_domain_destroy(xc, fuzzdomid);

            iter = 0;
            fuzzdomid = 0;

            if ( fork_vm(sinkdomid, &fuzzdomid) )
                make_fuzz_ready();
        }
    }

    close_trace(vmi);
    vmi_destroy(vmi);

done:
    if ( ptcov )
        close_pt();
    if ( fuzzdomid && !keep )
        xc_domain_destroy(xc, fuzzdomid);
    if ( sinkdomid && !keep )
        xc_domain_destroy(xc, sinkdomid);

    if ( sink_list )
    {
        if ( !builtin_list )
            g_slist_free_full(sink_list, g_free);
        else
            g_slist_free(sink_list);
    }

    xc_interface_close(xc);
    cs_close(&cs_handle);
    if ( input_file )
        fclose(input_file);

    if ( debug ) printf(" ############ DONE ##############\n");
    if ( logfile )
        close(out);

    return 0;
}
