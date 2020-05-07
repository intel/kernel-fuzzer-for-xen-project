bin_PROGRAMS = kernel-fuzzer

kernel_fuzzer_SOURCES = src/main.c src/private.h \
                        src/signal.c src/signal.h \
                        src/vmi.c src/vmi.h \
                        src/setup.c src/setup.h \
                        src/afl.c src/afl.h \
                        src/tracer.c src/tracer.h

kernel_fuzzer_LDADD   = $(LIBS) \
                        $(GLIB_LIBS) \
                        $(VMI_LIBS) \
                        $(JSONC_LIBS) \
                        $(CAPSTONE_LIBS)
kernel_fuzzer_CFLAGS  = -Wall -Wextra -fstack-protector \
                        $(CFLAGS) \
                        $(GLIB_CFLAGS) \
                        $(VMI_CFLAGS) \
                        $(JSONC_CFLAGS) \
                        $(CAPSTONE_CFLAGS)

EXTRA_DIST = configure.ac README.md \
             tools/README tools/Makefile tools/vmfork.go \
             patches/0001-AFL-Xen-mode.patch \
             testmodule/Makefile testmodule/testmodule.c
