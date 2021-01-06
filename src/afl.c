/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include "private.h"

/* Environment variable used to pass SHM ID to the called program. */
#define SHM_ENV_VAR         "__AFL_SHM_ID"
#define FORKSRV_FD          198

unsigned char *afl_area_ptr;
static unsigned int afl_inst_rms = MAP_SIZE;
static char *id_str;
unsigned long prev_loc;

void afl_rewind(void)
{
    prev_loc  = 0;
    memset(afl_area_ptr, 0, MAP_SIZE);
}

void afl_instrument_location(unsigned long cur_loc)
{
    if ( !id_str )
        return;

    cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
    cur_loc &= MAP_SIZE - 1;

    afl_area_ptr[cur_loc ^ prev_loc]++;
    prev_loc = cur_loc >> 1;
}

void afl_setup(void) {

    int shm_id;

    id_str = getenv(SHM_ENV_VAR);
    char *inst_r = getenv("AFL_INST_RATIO");

    if ( !id_str )
        return;

    if (inst_r) {
        unsigned int r = atoi(inst_r);

        if (r > 100) r = 100;
        if (!r) r = 1;

        afl_inst_rms = MAP_SIZE * r / 100;
    }

    if (id_str) {
        shm_id = atoi(id_str);
        afl_area_ptr = shmat(shm_id, NULL, 0);

        if (afl_area_ptr == (void*)-1) exit(1);

        /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
           so that the parent doesn't give up on us. */

        if (inst_r) afl_area_ptr[0] = 1;
    }

    /* Tell AFL we are alive */
    unsigned char tmp[4];
    if (write(FORKSRV_FD + 1, tmp, 4) == 4)
    {
        afl = true;
        afl_instrument_location(start_rip);
    }
}

/*
 * Let's wait for AFL to send us something down the pipe
 * and respond with a fake pid as if the forkserver was running.
 * We do this because we don't actually need to fork the process,
 * we have already forked the VM, so this is just to keep AFL happy.
 */
void afl_wait(void)
{
    unsigned char tmp[4];
    /* Whoops, parent dead? */
    if (read(FORKSRV_FD, tmp, 4) != 4)
    {
        afl = false;
        return;
    }

    pid_t pid = getpid();
    if (write(FORKSRV_FD + 1, &pid, 4) != 4)
        afl = false;
}

/* Send AFL the crash report */
void afl_report(bool crash)
{
    int32_t status = crash ? SIGABRT : 0;
    if (write(FORKSRV_FD + 1, &status, 4) != 4)
        afl = false;
}
