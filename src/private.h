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

#include <capstone.h>

#include "signal.h"
#include "vmi.h"
#include "afl.h"
#include "setup.h"
#include "tracer.h"
#include "forkvm.h"

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
addr_t address;
unsigned long limit;

xc_interface *xc;
vmi_instance_t parent_vmi, vmi;
os_t os;
addr_t target_pagetable;
addr_t start_rip;
page_mode_t pm;
int interrupted;
int vcpus;

bool harness_cpuid;
uint8_t start_byte;

csh cs_handle;

#endif
