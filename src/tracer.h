/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#ifndef TRACER_H
#define TRACER_H

#include <stdbool.h>
#include <libvmi/libvmi.h>

bool make_sink_ready(void);

bool setup_trace(vmi_instance_t vmi);
bool start_trace(vmi_instance_t vmi, addr_t address);
void close_trace(vmi_instance_t vmi);

void do_record_codecov(void);

#endif
