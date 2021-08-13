/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#ifndef SINK_H
#define SINK_H

#include "sink_handler.h"

struct sink {
    const char *function;
    addr_t vaddr;
    addr_t paddr;
    struct sink_handler *handler;
};

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
 *
 * Sink functions listed here that are not found in the JSON will be skipped.
 */
static struct sink sinks[] = {
    { .function = "panic" },
    { .function = "oops_begin" },

    /*
     * We interpret a page fault as a crash situation since we really shouldn't
     * encounter any. The VM forks are running without any devices so even if this
     * is a legitimate page-fault that would page memory back in, it won't be able
     * to do that since there is no disk.
     */
    { .function = "page_fault" }, // <5.8 kernels
    { .function = "asm_exc_page_fault" }, // >=5.8 kernels

    /*
     * Catch when KASAN starts to report an error it caught.
     * Demonstrate using the sink_handler extension. A callback is issued to a
     * pre-defined function when the sink is triggered that will determine how to
     * handle the sink. See sink_handler.h for more information.
     */
    { .function = "kasan_report", .handler = &kasan_report_handler },

    /*
     * Catch when UBSAN starts to report an error it caught.
     */
    { .function = "ubsan_prologue" },

    /*
     * Catch when KMSAN starts to report an error it caught.
     * See https://github.com/google/kmsan
     */
    { .function = "kmsan_report" },

    /*
     * You can manually define sinks by virtual address or physical address as well.
     * Or you can use the command-line options --sink-vaddr/--sink-paddr too.
     * Note that defining sinks on the command-line will disable using the built-in sinks
     * that are listed in here.
     */
    //{ .function = "custom sink", .vaddr = 0xffffffdeadbeef },
};

#endif
