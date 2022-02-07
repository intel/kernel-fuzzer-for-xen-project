/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include "private.h"

/* Environment variable used to pass SHM ID to the called program. */
#define SHM_ENV_VAR         "__AFL_SHM_ID"
#define SHM_FUZZ_ENV_VAR    "__AFL_SHM_FUZZ_ID"
#define FORKSRV_FD          198

/* Reporting options */
#define FS_OPT_ENABLED 0x80000001
#define FS_OPT_MAPSIZE 0x40000000
#define FS_OPT_SNAPSHOT 0x20000000
#define FS_OPT_AUTODICT 0x10000000
#define FS_OPT_SHDMEM_FUZZ 0x01000000
#define FS_OPT_NEWCMPLOG 0x02000000

#define FS_OPT_MAX_MAPSIZE ((0x00fffffeU >> 1) + 1)
#define FS_OPT_SET_MAPSIZE(x) \
  (x <= 1 || x > FS_OPT_MAX_MAPSIZE ? 0 : ((x - 1) << 1))

unsigned char *afl_area_ptr;
unsigned char *afl_input_ptr;
static unsigned int afl_inst_rms = MAP_SIZE;
static char *id_str;
static char *fuzz_str;
unsigned long prev_loc;

void afl_rewind(void)
{
    prev_loc  = 0;
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

void afl_setup(void)
{
    uint32_t status = FS_OPT_ENABLED | FS_OPT_MAPSIZE | FS_OPT_SET_MAPSIZE(MAP_SIZE);

    unsigned char tmp[4];
    int shm_id;

    id_str = getenv(SHM_ENV_VAR);
    if ( !id_str )
        return;

    shm_id = atoi(id_str);
    afl_area_ptr = shmat(shm_id, NULL, 0);

    if (afl_area_ptr == (void*)-1) exit(1);

    /* Get input via shared memory instead of file i/o */
    fuzz_str = getenv(SHM_FUZZ_ENV_VAR);
    if ( fuzz_str )
    {
        int shm_fuzz_id = atoi(fuzz_str);
        afl_input_ptr = shmat(shm_fuzz_id, NULL, 0);

        if (afl_input_ptr == (void*)-1) exit(1);

        status |= FS_OPT_SHDMEM_FUZZ;
    }

    memcpy(tmp, &status, 4);

    /* Tell AFL we are alive */
    if (write(FORKSRV_FD + 1, tmp, 4) == 4)
    {
        afl = true;
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
