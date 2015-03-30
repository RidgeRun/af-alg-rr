#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([af-alg-rr], [0.0.0], [carsten.behling@ridgerun.com])
AC_CONFIG_SRCDIR([src/ciphers.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror gnu])

OPENSSL_REQUIRED=1.0.0c

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AM_PROG_AR
LT_PREREQ([2.2.6])
LT_INIT

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([memory.h stdint.h stdlib.h string.h sys/param.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset socket strdup])

# Check for OpenSSL and obtain build info
PKG_CHECK_MODULES(OPENSSL, [
  openssl >= $OPENSSL_REQUIRED
], [
  AC_SUBST([OPENSSL_CFLAGS])
  AC_SUBST([OPENSSL_LIBS])
], [
  AC_MSG_ERROR([
      You need to install or upgrade the OpenSSL development
      packages on your system. On debian-based systems this is libssl-dev.
      The minimum version required is $OPENSSL_REQUIRED.
  ])
])

# Set the plugindir where plugins should be installed (for src/Makefile.am)
  plugindir="\$(libdir)/openssl-1.0.0"
AC_SUBST(plugindir)

# Set proper LDFLAGS for plugins
AC_SUBST(GST_PLUGIN_LDFLAGS)
AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT

