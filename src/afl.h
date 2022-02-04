/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#ifndef FORKSERVER_H
#define FORKSERVER_H

#define MAP_SIZE      (1ull << 16)

extern unsigned char *afl_area_ptr;
extern unsigned char *afl_input_ptr;

void afl_setup(void);
void afl_rewind(void);
void afl_wait(void);
void afl_report(bool crash);
void afl_instrument_location(unsigned long cur_loc);

#endif
