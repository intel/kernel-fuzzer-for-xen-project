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

#define XC_WANT_COMPAT_EVTCHN_API 1
#define XC_WANT_COMPAT_MAP_FOREIGN_API 1
#include <xenctrl.h>
#define LIBXL_API_VERSION 0x041300
#include <libxl.h>

#define LIBVMI_EXTRA_JSON
#define LIBVMI_EXTRA_GLIB
#include <libvmi/libvmi.h>
#include <libvmi/libvmi_extra.h>
#include <libvmi/events.h>
#include <libvmi/x86.h>

#include <json-c/json.h>
#include <glib.h>
#include <capstone.h>

#include "signal.h"
#include "vmi.h"
#include "afl.h"
#include "setup.h"
#include "tracer.h"

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

csh cs_handle;

#endif
