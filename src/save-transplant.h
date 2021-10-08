/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#ifndef SAVE_TRANSPLANT_H
#define SAVE_TRANSPLANT_H

#include <stdio.h>
#include <glib.h>
#include <libvmi/libvmi.h>

bool transplant_save_regs(vmi_instance_t vmi, const char *regf);
bool transplant_save_mem(vmi_instance_t vmi, const char *map_in, const char *map_out, const char *memf);

#endif
