/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include "vmi.h"
#include "signal.h"
#include "tracer.h"

static struct sigaction act;
extern int interrupted;
extern bool loopmode;
extern vmi_instance_t vmi;

#ifdef CODECOV_SIGNAL
static struct sigaction act2;
#endif

static void close_handler(int sig)
{
    interrupted = sig;
    loopmode = false;

    if ( vmi )
        vmi_pause_vm(vmi);
}

#ifdef CODECOV_SIGNAL
static void user_handler(int sig)
{
    (void)sig;

    do_record_codecov();
}
#endif

void setup_handlers(void)
{
    act.sa_handler = close_handler;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

#ifdef CODECOV_SIGNAL
    act2.sa_handler = user_handler;
    sigemptyset(&act2.sa_mask);
    sigaction(SIGUSR1,  &act2, NULL);
#endif
}
