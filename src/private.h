#ifndef PRIVATE_H
#define PRIVATE_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <sys/wait.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <libvmi/x86.h>

#include <capstone.h>

#include "signal.h"
#include "vmi.h"
#include "afl.h"
#include "setup.h"
#include "tracer.h"
#include "forkvm.h"

char *domain;
char *json;
char *input_file;
size_t input_size;
unsigned char *input;
uint32_t domid, forkdomid;
bool afl;
bool parent_ready;
bool crash;
bool setup;
bool debug;
addr_t address;
unsigned long limit;

xc_interface *xc;
vmi_instance_t vmi;
os_t os;
addr_t target_pagetable;
addr_t start_rip;
int interrupted;
int vcpus;

bool harness_cpuid;
uint8_t start_byte;

csh cs_handle;

#endif
