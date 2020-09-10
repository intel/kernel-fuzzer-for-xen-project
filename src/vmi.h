/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#ifndef VMI_H
#define VMI_H

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

bool setup_vmi(vmi_instance_t *vmi, char *domain, uint64_t domid, char *json, bool init_events, bool init_os);
void loop(vmi_instance_t vmi);

#endif
