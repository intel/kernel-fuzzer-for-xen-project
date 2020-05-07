AC_INIT([kernel-fuzzer], [1.0])
AM_INIT_AUTOMAKE([subdir-objects])

AC_CONFIG_SRCDIR(src/main.c)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS(config.h)

AC_CANONICAL_HOST
AC_PROG_CC
AM_PROG_CC_C_O
AM_SANITY_CHECK

PKG_CHECK_MODULES([GLIB], [glib-2.0],[],[AC_MSG_ERROR(GLib not found. Install missing package and re-run)])
PKG_CHECK_MODULES([VMI], [libvmi],[],[AC_MSG_ERROR(LibVMI not found. Install missing package and re-run)])
PKG_CHECK_MODULES([JSONC], [json-c],[],[AC_MSG_ERROR(json-c not found. Install missing package and re-run)])
PKG_CHECK_MODULES([CAPSTONE], [capstone],[],[AC_MSG_ERROR(Capstone not found. Install missing package and re-run)])

AC_CHECK_LIB(xenctrl, [xc_memshr_fork, xc_memshr_fork_reset], [],[AC_MSG_ERROR(libxc not found. Install missing package and re-run)])

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
