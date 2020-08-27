#include "private.h"
#include "sink.h"

/*
 * 1. start by disassembling code from the start address
 * 2. find next control-flow instruction and start monitoring it
 * 3. at control flow instruction remove monitor and create singlestep
 * 4. after a singlestep set start address to current RIP
 * 5. goto step 1
 */

static const char *traptype[] = {
    [VMI_EVENT_SINGLESTEP] = "singlestep",
    [VMI_EVENT_CPUID] = "cpuid",
    [VMI_EVENT_INTERRUPT] = "int3",
};

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
        case X86_INS_JAE:
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
        case X86_INS_RETF:
        case X86_INS_RETFQ:
            return true;
        default:
            break;
    }

    return false;
}

#define TRACER_CF_SEARCH_LIMIT 100u

static bool next_cf_insn(vmi_instance_t vmi, addr_t dtb, addr_t start)
{
    cs_insn *insn;
    size_t count;

    size_t read, search = 0;
    unsigned char buff[15];
    bool found = false;
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = dtb,
        .addr = start
    };

    while ( !found && search < TRACER_CF_SEARCH_LIMIT )
    {
        memset(buff, 0, 15);

        if ( VMI_FAILURE == vmi_read(vmi, &ctx, 15, buff, &read) && !read )
        {
            if ( debug ) printf("Failed to grab memory from 0x%lx with PT 0x%lx\n", start, dtb);
            goto done;
        }

        count = cs_disasm(cs_handle, buff, read, ctx.addr, 0, &insn);
        if ( !count )
        {
            if ( debug ) printf("No instruction was found at 0x%lx with PT 0x%lx\n", ctx.addr, dtb);
            goto done;
        }

        size_t j;
        for ( j=0; j<count; j++) {

            ctx.addr = insn[j].address + insn[j].size;

            if ( debug ) printf("Next instruction @ 0x%lx: %s, size %i!\n", insn[j].address, insn[j].mnemonic, insn[j].size);

            if ( is_cf(insn[j].id) )
            {
                next_cf_vaddr = insn[j].address;
                if ( VMI_FAILURE == vmi_pagetable_lookup(vmi, dtb, next_cf_vaddr, &next_cf_paddr) )
                {
                    if ( debug ) printf("Failed to lookup next instruction PA for 0x%lx with PT 0x%lx\n", next_cf_vaddr, dtb);
                    break;
                }

                found = true;

                if ( debug ) printf("Found next control flow instruction @ 0x%lx: %s!\n", next_cf_vaddr, insn[j].mnemonic);
                break;
            }
        }
        cs_free(insn, count);
    }

    if ( !found && debug )
        printf("Didn't find a control flow instruction starting from 0x%lx with a search limit %u! Counter: %lu\n",
               start, TRACER_CF_SEARCH_LIMIT, tracer_counter);

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
        if ( next_cf_insn(vmi, event->x86_regs->cr3, event->x86_regs->rip) )
            breakpoint_next_cf(vmi);

        return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
    }

    /*
     * Let's allow the control-flow instruction to execute
     * and catch where it continues using MTF singlestep.
     */
    if ( VMI_EVENT_INTERRUPT == event->type )
    {
        event->interrupt_event.reinject = 0;

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

bool make_sink_ready(void)
{
    vmi_instance_t sink_vmi = NULL;
    bool ret = false;

    if ( !setup_vmi(&sink_vmi, NULL, sinkdomid, json, false, true) )
        return ret;

    int c;
    for(c=0; c < __SINK_MAX; c++)
    {
        if ( !sink_vaddr[c] && VMI_FAILURE == vmi_translate_ksym2v(sink_vmi, sinks[c], &sink_vaddr[c]) )
        {
            if ( debug ) printf("Failed to find address for sink %s in the JSON\n", sinks[c]);
            goto done;
        }

        if ( !sink_paddr[c] && VMI_FAILURE == vmi_pagetable_lookup(sink_vmi, target_pagetable, sink_vaddr[c], &sink_paddr[c]) )
        {
            if ( debug ) printf("Failed to translate %s V2P 0x%lx\n", sinks[c], sink_vaddr[c]);
            goto done;
        }
        if ( VMI_FAILURE == vmi_read_pa(sink_vmi, sink_paddr[c], 1, &sink_backup[c], NULL) )
        {
            if ( debug ) printf("Failed to read %s PA 0x%lx\n", sinks[c], sink_paddr[c]);
            goto done;
        }
        if ( VMI_FAILURE == vmi_write_pa(sink_vmi, sink_paddr[c], 1, &cc, NULL) )
        {
            if ( debug ) printf("Failed to write %s PA 0x%lx\n", sinks[c], sink_paddr[c]);
            goto done;
        }

        if ( debug )
            printf("Setting breakpoint on sink %s 0x%lx -> 0x%lx, backup 0x%x\n",
                   sinks[c], sink_vaddr[c], sink_paddr[c], sink_backup[c]);
    }

    if ( debug ) printf("Sinks are ready\n");
    ret = true;

done:
    vmi_destroy(sink_vmi);
    return ret;
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

    if ( !next_cf_insn(vmi, target_pagetable, address) )
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
