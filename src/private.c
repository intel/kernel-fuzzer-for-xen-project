/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: MIT
 */

#include "private.h"

char *domain;
char *json;
FILE *input_file;
char *input_path;
size_t input_size;
size_t input_limit;
unsigned char *input;
uint32_t domid, sinkdomid, fuzzdomid;
bool afl;
bool parent_ready;
bool crash;
bool setup;
bool debug;
bool loopmode;
bool nocov;
bool ptcov;
addr_t address;
unsigned long limit;
const char* record_codecov;
const char* record_memaccess;
GHashTable *codecov;
GHashTable *memaccess;

xc_interface *xc;
vmi_instance_t parent_vmi, vmi;
os_t os;
addr_t target_pagetable;
addr_t start_rip;
page_mode_t pm;
int interrupted;
int vcpus;
GSList *doublefetch;

bool harness_cpuid;
bool extended_mark;
unsigned int magic_mark;
uint8_t start_byte;

csh cs_handle;

bool builtin_list;
GSList *sink_list;
