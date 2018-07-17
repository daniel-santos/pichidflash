#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([picus_behid],[1.7.0],[daniel.santos@pobox.com])
AC_CONFIG_SRCDIR([usb-libusb.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_AUX_DIR([autoscripts])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

AC_C_INLINE

# Checks for libraries.
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES(LIBUSB, libusb)

# Checks for header files.
AC_CHECK_HEADERS([stdbool.h stddef.h fcntl.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT16_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([munmap memset])


AC_CONFIG_FILES([Makefile])
AC_OUTPUT
