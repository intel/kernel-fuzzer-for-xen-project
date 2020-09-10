/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#ifndef TRACER_H
#define TRACER_H

#include "private.h"

bool make_sink_ready();

bool setup_trace(vmi_instance_t vmi);
bool start_trace(vmi_instance_t vmi, addr_t address);
void close_trace(vmi_instance_t vmi);

#endif
