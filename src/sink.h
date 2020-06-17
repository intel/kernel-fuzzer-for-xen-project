#ifndef SINK_H
#define SINK_H

/*
 * List all sink points here. When the kernel executes any of these functions
 * we will report a crash to AFL and stop the fuzzer.
 */
enum sink_enum {
    OOPS_HANDLER,
    __SINK_MAX
};

/* Now define what symbol each enum entry corresponds to in the debug json */
const char *sinks[] = {
    [OOPS_HANDLER] = "_kernel_oops_handler",
};

addr_t sink_vaddr[__SINK_MAX] =
{
    [0 ... __SINK_MAX-1] = 0,

    /*
     * You can manually define each sink's virtual address here. For example:
    [PAGE_FAULT] = 0xffffffdeadbeef,
     */

    [OOPS_HANDLER] = 0x1017b1
};

addr_t sink_paddr[__SINK_MAX] =
{
    [0 ... __SINK_MAX-1] = 0,

    /*
     * You can manually define each sink's physical address here. For example:
    [PAGE_FAULT] = 0xdeadbeef,
     */
};

uint8_t sink_backup[__SINK_MAX] = {0};

#endif
