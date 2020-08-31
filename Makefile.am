bin_PROGRAMS = kfx
kfx_SOURCES = src/main.c src/private.h \
              src/signal.c src/signal.h \
              src/vmi.c src/vmi.h \
              src/setup.c src/setup.h \
              src/afl.c src/afl.h \
              src/tracer.c src/tracer.h \
              src/forkvm.c src/forkvm.h \
              src/ptcov.c src/ptcov.h \
              src/sink.h

kfx_LDADD   = $(LIBS) $(VMI_LIBS) $(CAPSTONE_LIBS) $(LIBXC_LIBS) $(XENFMEM_LIBS) $(GLIB_LIBS)
kfx_CFLAGS  = -Wall -Wextra -fstack-protector -Wno-override-init \
              $(CFLAGS) $(VMI_CFLAGS) $(CAPSTONE_CFLAGS) $(LIBXC_CFLAGS) $(XENFMEM_CFLAGS) $(GLIB_CFLAGS)

if STATIC_LIBXDC
    noinst_LTLIBRARIES= libxdc.la
    libxdc_la_SOURCES= libxdc/src/cfg.c libxdc/src/disassembler.c libxdc/src/tnt_cache.c \
                       libxdc/src/decoder.c libxdc/src/libxdc.c libxdc/src/mmh3.c libxdc/src/trace_cache.c
    libxdc_la_CFLAGS= $(CAPSTONE_CFLAGS) -Ofast -fPIC -fvisibility=hidden -flto -finline-functions
    libxdc_la_LDFLAGS= $(CAPSTONE_LIBS) -flto
    kfx_LDADD+= libxdc.la
    kfx_CFLAGS+= -Ilibxdc
endif

bin_PROGRAMS += forkvm
forkvm_SOURCES = src/forkvm_main.c src/forkvm.c src/forkvm.h
forkvm_LDADD = $(LIBXC_LIBS)
forkvm_CFLAGS = $(LIBXC_CFLAGS)

bin_PROGRAMS +=  rwmem
rwmem_SOURCES = src/rwmem.c src/vmi.c src/vmi.h
rwmem_LDADD = $(LIBS) $(VMI_LIBS)
rwmem_CFLAGS = $(CFLAGS) $(VMI_CFLAGS)

bin_PROGRAMS += stepper
stepper_SOURCES = src/stepper.c src/vmi.c src/vmi.h src/signal.c src/signal.h
stepper_LDADD = $(LIBS) $(VMI_LIBS) $(CAPSTONE_LIBS) $(LIBXC_LIBS)
stepper_CFLAGS = $(CFLAGS) $(VMI_CFLAGS) $(CAPSTONE_CFLAGS) $(LIBXC_CFLAGS)

ACLOCAL_AMFLAGS=-I m4
EXTRA_DIST = configure.ac README.md \
             tools/README tools/Makefile tools/vmfork.go \
             patches/0001-AFL-Xen-mode.patch \
             testmodule/Makefile testmodule/testmodule.c
