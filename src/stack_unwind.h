/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#ifndef STACK_UNWIND_H
#define STACK_UNWIND_H

#include <stdbool.h>
#include <glib.h>
#include <libvmi/libvmi.h>

bool stack_unwind_init(void);
GSList* stack_unwind(vmi_instance_t vmi, x86_registers_t *regs, page_mode_t pm);
void stack_unwind_clear(void);

#endif
