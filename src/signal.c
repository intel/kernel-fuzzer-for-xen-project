/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include "vmi.h"
#include "signal.h"

static struct sigaction act;
extern int interrupted;
extern bool loopmode;
extern vmi_instance_t vmi;

static void close_handler(int sig)
{
    interrupted = sig;
    loopmode = false;

    if ( vmi )
        vmi_pause_vm(vmi);
}

void setup_handlers(void)
{
    act.sa_handler = close_handler;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);
}
