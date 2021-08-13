/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#ifndef SINK_EXTRA_H
#define SINK_EXTRA_H

struct sink;

typedef enum sink_callback_response {
     IGNORE,
     REPORT_CRASH,
     CONTINUE,
} sink_cb_response_t;

struct sink_extra {
    bool (*sink_init)(vmi_instance_t vmi, struct sink *s);
    sink_cb_response_t (*cb)(vmi_instance_t vmi, vmi_event_t *event, event_response_t *rsp, struct sink *s);
    void *data;
};

extern struct sink_extra kasan_report_extra;

#endif
