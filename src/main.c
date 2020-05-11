#include "private.h"

static bool inject_input(vmi_instance_t vmi)
{
    if ( !input_size )
        return true;

    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = target_pagetable,
        .addr = address
    };

    if ( input_limit && input_size > input_limit )
        input_size = input_limit;

    if ( debug ) printf("Writing %lu bytes of input to 0x%lx\n", input_size, address);

    bool ret = VMI_SUCCESS == vmi_write(vmi, &ctx, input_size, input, NULL);
    free(input);

    return ret;
}

static bool make_fork_ready()
{
    if ( !forkdomid )
        return false;

    if ( !setup_vmi(&vmi, NULL, forkdomid, NULL, true, false) )
    {
        fprintf(stderr, "Unable to start VMI on domain\n");
        return false;
    }

    setup_trace(vmi);

    if ( debug ) printf("Fork ready\n");

    return true;
}

static bool fuzz_fork(void)
{
    if ( !forkdomid )
        return false;

    crash = 0;

    if ( afl ) afl_wait();

    afl_get_input();

    if ( !start_trace(vmi, start_rip) )
        return false;
    if ( !inject_input(vmi) )
        return false;

    if ( debug ) printf("Starting fuzz loop\n");
    loop(vmi);
    if ( debug ) printf("Stopping fuzz loop.\n");

    vmi_pagecache_flush(vmi);
    vmi_v2pcache_flush(vmi, target_pagetable);
    vmi_pidcache_flush(vmi);
    vmi_rvacache_flush(vmi);
    vmi_symcache_flush(vmi);

    int rc = xc_memshr_fork_reset(xc, forkdomid);

    if ( afl ) afl_report(crash);
    else printf("Result: %s\n", crash ? "crash" : "no crash");

    return afl && !rc;
}

static void usage(void)
{
    printf("Inputs required for SETUP step:\n");
    printf("\t  --setup\n");
    printf("\t  --domain <domain name> OR --domid <domain id>\n");
    printf("\t  --json <path to kernel debug json>\n");
    printf("\tOptional inputs:\n");
    printf("\t  --harness cpuid|breakpoint (default is cpuid)\n");
    printf("\t  --start-byte <byte> (used to replace the starting breakpoint harness)\n");

    printf("\n\n");
    printf("Inputs required for FUZZING step:\n");
    printf("\t  --input <path to input file> or @@ with AFL\n");
    printf("\t  --address <kernel virtual address to inject input to>\n");
    printf("\t  --domain <domain name> OR --domid <domain id>\n");
    printf("\t  --json <path to kernel debug json>\n");
    printf("\tOptional inputs:\n");
    printf("\t  --limit <limit FUZZING execution to # of CF instructions>\n");
    printf("\t  --input-limit <limit input size>\n");
    printf("\t  --harness cpuid|breakpoint (default is cpuid)\n");

    printf("\n\n");
    printf("Optional global inputs:\n");
    printf("\t--debug\n");
    printf("\t--logfile <path to logfile>\n");
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
        {NULL, 0, NULL, 0}
    };
    const char* opts = "d:i:j:f:a:l:F:H:S:svh";
    limit = ~0;

    harness_cpuid = true;
    input_file = NULL;
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
            input_file = optarg;
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
        case 'h': /* fall-through */
        default:
            usage();
            return -1;
        };
    }

    if ( (!domain && !domid) || !json || (!address && !setup) )
    {
        usage();
        return -1;
    }

    if ( !harness_cpuid && !start_byte )
    {
        printf("For breakpoint harness --start-byte with a value must be provided (NOP is always a good option, 0x90)\n");
        return -1;
    }

    if ( logfile )
    {
        out = open(logfile, O_RDWR|O_CREAT|O_APPEND, 0600);
        if (-1 == dup2(out, fileno(stdout))) return -1;
        if (-1 == dup2(out, fileno(stderr))) return -1;
    }

    if ( debug ) printf ("############ START ################\n");

    setup_handlers();

    bool parent_ready = make_parent_ready();

    if ( setup )
        return parent_ready ? 0 : -1;

    if ( !(xc = xc_interface_open(0, 0, 0)) )
    {
        fprintf(stderr, "Failed to grab xc interface\n");
        goto done;
    }

    if ( cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle) )
        return false;

    if ( !fork_vm() )
    {
        fprintf(stderr, "Domain fork failed\n");
        goto done;
    }

    printf("Fork VM created: %i\n", forkdomid);

    afl_setup();

    afl_dummy_instrument();

    make_fork_ready();

    printf("Starting fuzzer\n");

    while ( fuzz_fork() ) {};

    close_trace(vmi);
    vmi_destroy(vmi);

done:
    if ( forkdomid )
        xc_domain_destroy(xc, forkdomid);
    xc_interface_close(xc);
    cs_close(&cs_handle);

    if ( debug ) printf(" ############ DONE ##############\n");
    if ( logfile )
        close(out);

    return 0;
}
