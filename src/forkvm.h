/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#ifndef FORKVM_H
#define FORKVM_H

#include <xenctrl.h>
#define LIBXL_API_VERSION 0x041300
#include <libxl.h>
#include <libxl_utils.h>

bool fork_vm(uint32_t domid, char *name_sig, char *name_flavor, uint32_t *forkdomid);

#endif
