#include "private.h"

/*
 * List all sink points here. When the kernel executes any of these functions
 * we will report a crash to AFL and stop the fuzzer.
 */
enum sink_enum {
    OOPS_BEGIN,
    PANIC,
    __SINK_MAX
};
/* Now define what symbol each enum entry corresponds to in the debug json */
static const char *sinks[] = {
    [PANIC] = "panic",

    /*
     * We can define as many sink points as we want. These sink points don't have
     * to be strictly functions that handle "crash" situations. We can define any
     * code location as a sink point that we would want to know about if it is reached
     * during fuzzing. For example the testmodule triggering a NULL-deref doesn't crash
     * the kernel, it simply causes an "oops" message to be printed to the kernel logs.
     * However, if there is an input that causes something like that then it warrants
     * being recorded.
     *
     * So in essence we can define the sink points as anything of interest that we would
     * want AFL to record if its reached.
     */
    [OOPS_BEGIN] = "oops_begin",
};

/* !!!!!!!!!!!!!!!! */
/* You don't need to change anything below if you only want to add new sinks */
/* !!!!!!!!!!!!!!!! */

static addr_t sink_vaddr[__SINK_MAX];
static addr_t sink_paddr[__SINK_MAX];
static uint8_t sink_backup[__SINK_MAX];
static const char *traptype[] = {
    [VMI_EVENT_SINGLESTEP] = "singlestep",
    [VMI_EVENT_CPUID] = "cpuid",
    [VMI_EVENT_INTERRUPT] = "int3",
};

 /*
 * 1. start by disassembling code from the start address
 * 2. find next control-flow instruction and start monitoring it
 * 3. at control flow instruction remove monitor and create singlestep
 * 4. after a singlestep set start address to current RIP
 * 5. goto step 1
 */

#define TRACER_BUFFER_SIZE 256

unsigned long tracer_counter;

extern int interrupted;
extern csh cs_handle;

static addr_t next_cf_vaddr;
static addr_t next_cf_paddr;

static uint8_t cc = 0xCC;
static uint8_t cf_backup;

static vmi_event_t singlestep_event, cc_event, cpuid_event;

static void breakpoint_next_cf(vmi_instance_t vmi)
{
    if ( VMI_SUCCESS == vmi_read_pa(vmi, next_cf_paddr, 1, &cf_backup, NULL) &&
         VMI_SUCCESS == vmi_write_pa(vmi, next_cf_paddr, 1, &cc, NULL) )
    {
        if ( debug ) printf("[TRACER] Next CF: 0x%lx -> 0x%lx\n", next_cf_vaddr, next_cf_paddr);
    }
}

static inline bool is_cf(unsigned int id)
{
    switch ( id )
    {
        case X86_INS_JA:
        case X86_INS_JBE:
        case X86_INS_JB:
        case X86_INS_JCXZ:
        case X86_INS_JECXZ:
        case X86_INS_JE:
        case X86_INS_JGE:
        case X86_INS_JG:
        case X86_INS_JLE:
        case X86_INS_JL:
        case X86_INS_JMP:
        case X86_INS_LJMP:
        case X86_INS_JNE:
        case X86_INS_JNO:
        case X86_INS_JNP:
        case X86_INS_JNS:
        case X86_INS_JO:
        case X86_INS_JP:
        case X86_INS_JRCXZ:
        case X86_INS_JS:
        case X86_INS_CALL:
        case X86_INS_RET:
            return true;
        default:
            break;
    }

    return false;
}

static bool next_cf_insn(vmi_instance_t vmi, addr_t start)
{
    cs_insn *insn;
    size_t count;

    size_t read;
    unsigned char buff[TRACER_BUFFER_SIZE] = { 0 };
    bool found = false;
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = target_pagetable,
        .addr = start
    };

    if ( VMI_FAILURE == vmi_read(vmi, &ctx, TRACER_BUFFER_SIZE, buff, &read) )
    {
        if ( debug ) printf("Failed to grab memory from 0x%lx with PT 0x%lx\n", start, target_pagetable);
        crash = 1; // May be the result of a currupt branch
        goto done;
    }

    count = cs_disasm(cs_handle, buff, read, start, 0, &insn);
    if ( count ) {
        size_t j;
        for ( j=0; j<count; j++) {
             if ( debug ) printf("Next instruction @ 0x%lx: %s!\n", insn[j].address, insn[j].mnemonic);

             if ( is_cf(insn[j].id) )
             {
                next_cf_vaddr = insn[j].address;
                if ( VMI_FAILURE == vmi_pagetable_lookup(vmi, target_pagetable, next_cf_vaddr, &next_cf_paddr) )
                {
                    if ( debug ) printf("Failed to lookup next instruction PA for 0x%lx with PT 0x%lx\n", next_cf_vaddr, target_pagetable);
                    break;
                }

                found = true;

                if ( debug ) printf("Found next control flow instruction @ 0x%lx: %s!\n", next_cf_vaddr, insn[j].mnemonic);
                break;
             }
        }
        cs_free(insn, count);
    }

    if ( !found )
        if ( debug ) printf("Didn't find a control flow instruction in %u bytes starting from 0x%lx! Counter: %lu\n", TRACER_BUFFER_SIZE, start, tracer_counter);

done:
    return found;
}

static event_response_t tracer_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    if ( debug ) printf("[TRACER %s] 0x%lx. Limit: %lu/%lu\n", traptype[event->type], event->x86_regs->rip, tracer_counter, limit);

    int c;
    for (c=0; c < __SINK_MAX; c++)
    {
        if ( sink_vaddr[c] == event->x86_regs->rip )
        {
            vmi_pause_vm(vmi);
            interrupted = 1;
            crash = 1;

            if ( debug ) printf("\t Sink %s! Tracer counter: %lu. Crash: %i.\n", sinks[c], tracer_counter, crash);

            if ( VMI_EVENT_INTERRUPT == event->type )
                event->interrupt_event.reinject = 0;

            if ( VMI_EVENT_SINGLESTEP == event->type )
                return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;

            return 0;
        }
    }

    if ( VMI_EVENT_CPUID == event->type )
    {
        if ( debug ) printf("CPUID leaf %x\n", event->cpuid_event.leaf);
        if ( event->cpuid_event.leaf == 0x13371337 )
        {
            // Harness signal on finish
            vmi_pause_vm(vmi);
            interrupted = 1;
            if ( debug ) printf("\t Harness signal on finish\n");
            return 0;
        }

        event->x86_regs->rip += event->cpuid_event.insn_length;
        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

    afl_instrument_location(event->x86_regs->rip);

    if ( VMI_EVENT_SINGLESTEP == event->type )
    {
        if ( next_cf_insn(vmi, event->x86_regs->rip) )
            breakpoint_next_cf(vmi);
        else
        {
            if ( debug ) printf("Pausing VM in singlestep cb\n");
            vmi_pause_vm(vmi);
            interrupted = 1;
        }

        return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
    }

    /*
     * Let's allow the control-flow instruction to execute
     * and catch where it continues using MTF singlestep.
     */
    if ( VMI_EVENT_INTERRUPT == event->type )
    {
        /*
         * This is not a SINK breakpoint and it's not the next CF either.
         * Need to reinject if we are using CPUID as the harness.
         * Otherwise this is the end harness.
         */
        if ( event->x86_regs->rip != next_cf_vaddr )
        {
            if ( harness_cpuid )
            {
                if ( debug ) printf("\t Reinjecting unexpected breakpoint at 0x%lx\n", event->x86_regs->rip);
                event->interrupt_event.reinject = 1;
                return 0;
            }

            // Harness signal on finish
            vmi_pause_vm(vmi);
            interrupted = 1;
            if ( debug ) printf("\t Harness signal on finish\n");
            return 0;
        }

        /* We are at the expected breakpointed CF instruction */
        event->interrupt_event.reinject = 0;
        vmi_write_pa(vmi, next_cf_paddr, 1, &cf_backup, NULL);

        tracer_counter++;

        if ( limit == ~0ul || tracer_counter < limit )
            return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;

        if ( debug ) printf("Hit the tracer limit: %lu\n", tracer_counter);
        vmi_pause_vm(vmi);
        interrupted = 1;
    }

    return 0;
}

/*
 * If you don't care about the parent after the fuzzing is done
 * you could do this step in setup_sinks(), that way the parent
 * already has the sinks breakpointed before the fork.
 * Saves you a couple full-page copies that we otherwise do for
 * each fork. Can improve performance a bit.
 */
bool setup_sinks(vmi_instance_t vmi)
{
    int c;
    for(c=0; c < __SINK_MAX; c++)
    {
        if ( VMI_FAILURE == vmi_translate_ksym2v(vmi, sinks[c], &sink_vaddr[c]) )
        {
            if ( debug ) printf("Failed to find %s\n", sinks[c]);
            return false;
        }

        if ( VMI_FAILURE == vmi_translate_kv2p(vmi, sink_vaddr[c], &sink_paddr[c]) )
            return false;
        if ( VMI_FAILURE == vmi_read_pa(vmi, sink_paddr[c], 1, &sink_backup[c], NULL) )
            return false;
        if ( VMI_FAILURE == vmi_write_pa(vmi, sink_paddr[c], 1, &cc, NULL) )
            return false;

        if ( debug )
            printf("[TRACER] Setting breakpoint on sink %s 0x%lx -> 0x%lx, backup 0x%x\n",
                   sinks[c], sink_vaddr[c], sink_paddr[c], sink_backup[c]);
    }

    return true;
}

void clear_sinks(vmi_instance_t vmi)
{
    int c;
    for(c=0; c < __SINK_MAX; c++)
        vmi_write_pa(vmi, sink_paddr[c], 1, &sink_backup[c], NULL);
}

bool setup_trace(vmi_instance_t vmi)
{
    if ( debug ) printf("Setup trace\n");

    SETUP_SINGLESTEP_EVENT(&singlestep_event, 1, tracer_cb, 0);
    SETUP_INTERRUPT_EVENT(&cc_event, tracer_cb);

    if ( VMI_FAILURE == vmi_register_event(vmi, &singlestep_event) )
        return false;
    if ( VMI_FAILURE == vmi_register_event(vmi, &cc_event) )
        return false;

    if ( harness_cpuid )
    {
        cpuid_event.version = VMI_EVENTS_VERSION;
        cpuid_event.type = VMI_EVENT_CPUID;
        cpuid_event.callback = tracer_cb;

        if ( VMI_FAILURE == vmi_register_event(vmi, &cpuid_event) )
            return false;
    }

    if ( debug ) printf("Setup trace finished\n");
    return true;
}

bool start_trace(vmi_instance_t vmi, addr_t address) {
    if ( debug ) printf("Starting trace from 0x%lx.\n", address);

    next_cf_vaddr = 0;
    next_cf_paddr = 0;
    tracer_counter = 0;

    if ( !next_cf_insn(vmi, address) )
    {
        if ( debug ) printf("Failed starting trace from 0x%lx\n", address);
        return false;
    }

    breakpoint_next_cf(vmi);
    return true;
}

void close_trace(vmi_instance_t vmi) {
    vmi_clear_event(vmi, &singlestep_event, NULL);
    vmi_clear_event(vmi, &cc_event, NULL);

    if ( harness_cpuid )
        vmi_clear_event(vmi, &cpuid_event, NULL);

    if ( debug ) printf("Closing tracer\n");
}
