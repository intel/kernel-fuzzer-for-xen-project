/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#ifndef FORKVM_H
#define FORKVM_H

#include <xenctrl.h>
#define LIBXL_API_VERSION 0x041300
#include <libxl.h>

bool fork_vm(uint32_t domid, uint32_t *forkdomid);

#endif
