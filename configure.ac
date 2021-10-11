AC_INIT([kernel-fuzzer], [1.0])
AM_INIT_AUTOMAKE([1.14 foreign subdir-objects])
LT_INIT

AC_CONFIG_SRCDIR(src/main.c)
AC_CONFIG_HEADERS(config.h)
AC_CONFIG_MACRO_DIRS([m4])

AC_CANONICAL_HOST
AC_PROG_CC
AC_PROG_CC_C99
AM_SANITY_CHECK

AC_ARG_ENABLE([xen],
      [AS_HELP_STRING([--disable-xen],
         [Build tools that work on Xen only @<:@no@:>@])],
      [with_xen=$enableval],
      [with_xen=yes])

AS_IF([test x"$with_xen" = x"yes"], [
    PKG_CHECK_MODULES([LIBXC], [xencontrol >= 4.15.0],[],[AC_MSG_ERROR(libxc not found. Install missing package and re-run)])
    PKG_CHECK_MODULES([XENFMEM], [xenforeignmemory >= 1.3],[],[AC_MSG_ERROR(libxenforeignmemory not found. Install missing package and re-run)])
    AC_CHECK_HEADERS([libxl.h], [], [AC_MSG_ERROR(libxl.h not found. Install missing package and re-run)])
    AC_CHECK_HEADERS([xen/xen.h], [], [AC_MSG_ERROR(xen/xen.h not found. Install missing package and re-run)])

    AC_DEFINE([HAVE_XEN], 1, [Have Xen])

    # Build static libxdc if the submodule is checked out
    AC_CHECK_FILES([libxdc/libxdc.h libxdc/src/decoder.c], [static_libxdc=yes], [static_libxdc=no])
    # Check if its installed and then just link dynamically
    AS_IF([test x"$static_libxdc" = x"yes"], [], [
        AC_CHECK_HEADERS([libxdc.h], [], [AC_MSG_ERROR(libxdc not found. Check out git submodule or install dynamically.)])
        AC_CHECK_LIB(xdc, [libxdc_init], [], [AC_MSG_ERROR(libxdc not found. Check out git submodule or install dynamically.)])
        ])
],[])

AM_CONDITIONAL([WITH_XEN], [test x"$with_xen" = xyes])
AM_CONDITIONAL([STATIC_LIBXDC], [test x"$static_libxdc" = "xyes"])

PKG_CHECK_MODULES([VMI], [libvmi],[],[AC_MSG_ERROR(LibVMI not found. Install missing package and re-run)])
PKG_CHECK_MODULES([CAPSTONE], [capstone >= 4.0.2],[],[AC_MSG_ERROR(Capstone not found. Install missing package and re-run)])
PKG_CHECK_MODULES([GLIB], [glib-2.0],[],[AC_MSG_ERROR(glib-2.0 not found. Install missing package and re-run)])
PKG_CHECK_MODULES([UNWIND], [libunwind-generic],[],[AC_MSG_ERROR(libunwind not found. Install missing package and re-run)])
AC_CHECK_HEADERS([math.h], [], [AC_MSG_ERROR([math.h not usable. Install missing package and re-run])])
AC_CHECK_LIB(m, ceil, [], [AC_MSG_ERROR([libm not found])])

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
