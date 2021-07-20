/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#ifndef PRIVATE_H
#define PRIVATE_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <glib.h>
#include <capstone.h>

#include "signal.h"
#include "vmi.h"
#include "afl.h"
#include "setup.h"
#include "tracer.h"
#include "forkvm.h"
#include "ptcov.h"
#include "sink.h"

extern char *domain;
extern char *json;
extern FILE *input_file;
extern char *input_path;
extern size_t input_size;
extern size_t input_limit;
extern unsigned char *input;
extern uint32_t domid, sinkdomid, fuzzdomid;
extern bool afl;
extern bool parent_ready;
extern bool crash;
extern bool setup;
extern bool debug;
extern bool loopmode;
extern bool nocov;
extern bool ptcov;
extern bool auto_address;
extern addr_t address;
extern unsigned long limit;
extern const char* record_codecov;
extern const char* record_memaccess;
extern GHashTable *codecov;
extern GHashTable *memaccess;

extern xc_interface *xc;
extern vmi_instance_t vmi;
extern os_t os;
extern addr_t target_pagetable;
extern addr_t start_rip;
extern page_mode_t pm;
extern int interrupted;
extern int vcpus;
extern GSList* doublefetch;

extern bool harness_cpuid;
extern bool extended_mark;
extern unsigned int magic_mark;
extern uint8_t start_byte;

extern csh cs_handle;

extern bool builtin_list;
extern GSList *sink_list;

#endif
