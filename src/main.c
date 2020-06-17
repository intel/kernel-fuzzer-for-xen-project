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

    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = target_pagetable,
        .addr = address
    };

    if ( debug ) printf("Writing %lu bytes of input to 0x%lx\n", input_size, address);

    return VMI_SUCCESS == vmi_write(vmi, &ctx, input_size, input, NULL);
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

    if ( afl )
    {
        afl_rewind(start_rip);
        afl_wait();
    }

    get_input();

    if ( !loopmode && !start_trace(vmi, start_rip) )
        return false;
    if ( !inject_input(vmi) )
    {
        fprintf(stderr, "Injecting input failed\n");
        return false;
    }

    if ( debug ) printf("Starting fuzz loop\n");
    loop(vmi);
    if ( debug ) printf("Stopping fuzz loop.\n");

    vmi_pagecache_flush(vmi);
    vmi_v2pcache_flush(vmi, target_pagetable);
    vmi_pidcache_flush(vmi);
    vmi_rvacache_flush(vmi);
    vmi_symcache_flush(vmi);

    int rc = xc_memshr_fork_reset(xc, forkdomid);
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

    return ret && !rc;
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
    printf("\t  --input-limit <limit input size>\n");
    printf("\t  --address <kernel virtual address to inject input to>\n");
    printf("\t  --domain <domain name> OR --domid <domain id>\n");
    printf("\t  --json <path to kernel debug json>\n");
    printf("\tOptional inputs:\n");
    printf("\t  --limit <limit FUZZING execution to # of CF instructions>\n");
    printf("\t  --harness cpuid|breakpoint (default is cpuid)\n");
    printf("\t  --loopmode (Run in a loop without coverage trace, for example using /dev/urandom as input)\n");
    printf("\t  --refork <create new fork after # of executions>\n");

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
        {"refork", required_argument, NULL, 'r'},
        {"loopmode", no_argument, NULL, 'O'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "d:i:j:f:a:l:F:H:S:svhO";
    limit = ~0;
    unsigned long refork = 0;

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
            break;
        case 'h': /* fall-through */
        default:
            usage();
            return -1;
        };
    }

    if ( (!domain && !domid) || (!address && !setup) || (!setup && (!input_path || !input_limit)) )
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

    if ( cs_open(CS_ARCH_X86, pm == VMI_PM_IA32E ? CS_MODE_64 : CS_MODE_32, &cs_handle) )
    {
        fprintf(stderr, "Capstone init failed\n");
        goto done;
    }

    if ( !fork_vm() )
    {
        fprintf(stderr, "Domain fork failed\n");
        goto done;
    }

    afl_setup();

    input_file = fopen(input_path,"r"); // Sanity check
    if ( !input_file )
    {
        printf("Failed to open input file %s\n", input_path);
        goto done;
    }
    fclose(input_file); // Closing for now, will reopen when needed
    input_file = NULL;

    if ( !afl ) printf("Fork VM created: %i\n", forkdomid);

    make_fork_ready();

    if ( debug ) printf("Starting fuzzer\n");

    if ( loopmode ) printf("Running in loopmode\n");
    else if ( afl )  printf("Running in AFL mode\n");
    else printf("Running in standalone mode\n");

    unsigned long iter = 0, t = time(0), cycle = 0;

    while ( fuzz_fork() )
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
            xc_domain_destroy(xc, forkdomid);

            iter = 0;
            forkdomid = 0;

            if ( fork_vm() )
                make_fork_ready();
        }
    }

    close_trace(vmi);
    vmi_destroy(vmi);

done:
    if ( parent_vmi )
    {
        clear_sinks(parent_vmi);
        vmi_destroy(parent_vmi);
    }
    if ( forkdomid )
        xc_domain_destroy(xc, forkdomid);
    xc_interface_close(xc);
    cs_close(&cs_handle);
    if ( input_file )
        fclose(input_file);

    if ( debug ) printf(" ############ DONE ##############\n");
    if ( logfile )
        close(out);

    return 0;
}
