#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([pic_usb_flash],[1.0.0],[daniel.santos@pobox.com])
AC_CONFIG_SRCDIR([usb-libusb.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_AUX_DIR([autoscripts])
AC_CANONICAL_TARGET
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE

# Detect the target system
case "${target_os}" in
    cygwin*|mingw*)
        AC_DEFINE(TARGET_WINDOWS, 1, [Build target is Windows])
        ;;
    darwin*)
        AC_DEFINE(TARGET_OSX, 1, [Build target is Mac])
        ;;
esac

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_C_INLINE

# Checks for libraries.
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES(LIBUSB, libusb)

# Checks for header files.
AC_CHECK_HEADERS([stddef.h fcntl.h string.h unistd.h])
AC_CHECK_HEADER_STDBOOL

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT16_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([munmap memset])

AC_ARG_ENABLE([debug],
    AS_HELP_STRING([--disable-debug], [Omit verbose debug code for formatting,
        colorizing, and printing URBs and .hex file records that are useful
        when troubleshooting bootloader problems, but make the executable
        larger.]),
    [],
    [enable_debug=yes])

if test x"$enable_debug" = xyes ; then
    AC_DEFINE(VERBOSE_DEBUG, 1, [Disable to trim code size a little bit.])
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
