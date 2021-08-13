/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#ifndef SINK_HANDLER_H
#define SINK_HANDLER_H

struct sink;

/*
 * The defined sink callback can determine how to handle the sink.
 *   IGNORE: stop execution but don't report a crash
 *   REPORT_CRASH: stop execution and report crash
 *   CONTINUE: don't stop execution, don't report a crash
 */
typedef enum sink_callback_response {
     REPORT_CRASH,
     IGNORE,
     CONTINUE,
} sink_cb_response_t;

struct sink_handler {
    bool (*init)(vmi_instance_t vmi, struct sink *s);
    sink_cb_response_t (*cb)(vmi_instance_t vmi, vmi_event_t *event, event_response_t *rsp, struct sink *s);
    void *data;
};

extern struct sink_handler kasan_report_handler;

#endif
