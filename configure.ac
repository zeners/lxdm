#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([lxdm], [0.1], [http://lxde.org/])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_CONFIG_SRCDIR([src/lxdm.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AM_PROG_CC_C_O

# Checks for libraries.
AC_CHECK_LIB([Xmu], [XmuClientWindow])
AC_CHECK_LIB([crypt], [crypt])
AC_CHECK_LIB([pam], [pam_open_session])

# Checks for header files.
AC_PATH_X
AC_CHECK_HEADERS([shadow.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([atexit endpwent getspnam getusershell memset putenv strstr])

IT_PROG_INTLTOOL([0.40.0])

pkg_modules="gtk+-2.0 >= 2.12.0"
PKG_CHECK_MODULES(GTK, [$pkg_modules])
AC_SUBST(GTK_CFLAGS)
AC_SUBST(GTK_LIBS)

GETTEXT_PACKAGE=lxdm
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE", [Gettext package.])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	po/Makefile.in
    data/Xsession
])
AC_OUTPUT
