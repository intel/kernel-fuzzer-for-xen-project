bin_PROGRAMS = kfx forkvm rwmem stepper

kfx_SOURCES = src/main.c src/private.h \
              src/signal.c src/signal.h \
              src/vmi.c src/vmi.h \
              src/setup.c src/setup.h \
              src/afl.c src/afl.h \
              src/tracer.c src/tracer.h \
              src/forkvm.c src/forkvm.h \
              src/sink.h

kfx_LDADD   = $(LIBS) \
              $(VMI_LIBS) \
              $(CAPSTONE_LIBS)
kfx_CFLAGS  = -Wall -Wextra -fstack-protector \
              -Wno-override-init \
              $(CFLAGS) \
              $(VMI_CFLAGS) \
              $(CAPSTONE_CFLAGS)

forkvm_SOURCES = src/forkvm_main.c src/forkvm.c src/forkvm.h

rwmem_SOURCES = src/rwmem.c src/vmi.c src/vmi.h
rwmem_LDADD = $(LIBS) $(VMI_LIBS)
rwmem_CFLAGS = $(CFLAGS) $(VMI_CFLAGS)

stepper_SOURCES = src/stepper.c src/vmi.c src/vmi.h src/signal.c src/signal.h
stepper_LDADD = $(LIBS) $(VMI_LIBS) $(CAPSTONE_LIBS)
stepper_CFLAGS = $(CFLAGS) $(VMI_CFLAGS) $(CAPSTONE_CFLAGS)

EXTRA_DIST = configure.ac README.md \
             tools/README tools/Makefile tools/vmfork.go \
             patches/0001-AFL-Xen-mode.patch \
             testmodule/Makefile testmodule/testmodule.c
