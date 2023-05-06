#!/bin/bash -norc
dnl	This file is an input file used by the GNU "autoconf" program to
dnl	generate the file "configure", which is run during Tcl installation
dnl	to configure the system for the local environment.

#
#-----------------------------------------------------------------------
# This is the configure.ac for the TclTLS extension.  The only places you
# should need to modify this file are marked by the string __CHANGE__.
#-----------------------------------------------------------------------

#-----------------------------------------------------------------------
# Set your package name and version numbers here.
#
# This initializes the environment with PACKAGE_NAME and PACKAGE_VERSION
# set as provided.  These will also be added as -D defs in your Makefile
# so you can encode the package version directly into the source files.
# This will also define a special symbol for Windows (BUILD_<PACKAGE_NAME>
# so that we create the export library with the dll.
#-----------------------------------------------------------------------

AC_INIT(tls,1.8.0)

#--------------------------------------------------------------------
# Call TEA_INIT as the first TEA_ macro to set up initial vars.
# This will define a ${TEA_PLATFORM} variable == "unix" or "windows"
# as well as PKG_LIB_FILE and PKG_STUB_LIB_FILE.
#--------------------------------------------------------------------

TEA_INIT()

AC_CONFIG_AUX_DIR(tclconfig)

#--------------------------------------------------------------------
# Load the tclConfig.sh file
#--------------------------------------------------------------------

TEA_PATH_TCLCONFIG
TEA_LOAD_TCLCONFIG

#--------------------------------------------------------------------
# Load the tkConfig.sh file if necessary (Tk extension)
#--------------------------------------------------------------------

#TEA_PATH_TKCONFIG
#TEA_LOAD_TKCONFIG

#-----------------------------------------------------------------------
# Handle the --prefix=... option by defaulting to what Tcl gave.
# Must be called after TEA_LOAD_TCLCONFIG and before TEA_SETUP_COMPILER.
#-----------------------------------------------------------------------

TEA_PREFIX

#-----------------------------------------------------------------------
# Standard compiler checks.
# This sets up CC by using the CC env var, or looks for gcc otherwise.
# This also calls AC_PROG_CC and a few others to create the basic setup
# necessary to compile executables.
#-----------------------------------------------------------------------

TEA_SETUP_COMPILER

#-----------------------------------------------------------------------
# __CHANGE__
# Specify the C source files to compile in TEA_ADD_SOURCES,
# public headers that need to be installed in TEA_ADD_HEADERS,
# stub library C source files to compile in TEA_ADD_STUB_SOURCES,
# and runtime Tcl library files in TEA_ADD_TCL_SOURCES.
# This defines PKG(_STUB)_SOURCES, PKG(_STUB)_OBJECTS, PKG_HEADERS
# and PKG_TCL_SOURCES.
#-----------------------------------------------------------------------

TEA_ADD_SOURCES([tls.c tlsBIO.c tlsIO.c tlsX509.c])
TEA_ADD_HEADERS([tls.h])
TEA_ADD_INCLUDES([-I$(SSL_INCLUDE_DIR)])
TEA_ADD_LIBS([])
TEA_ADD_CFLAGS([])
TEA_ADD_STUB_SOURCES([])
TEA_ADD_TCL_SOURCES([tls.tcl])

#--------------------------------------------------------------------
#
# You can add more files to clean if your extension creates any extra
# files by extending CLEANFILES.
# Add pkgIndex.tcl if it is generated in the Makefile instead of ./configure
# and change Makefile.in to move it from CONFIG_CLEAN_FILES to BINARIES var.
#
# A few miscellaneous platform-specific items:
# TEA_ADD_* any platform specific compiler/build info here.
#--------------------------------------------------------------------

CONFIG_CLEAN_FILES="$CONFIG_CLEAN_FILES tls.tcl.h.* config.log config.status dh_params.h.new dh_params.h Makefile pkgIndex.tcl tcltls.a.linkadd tcltls.syms"
if test "${TEA_PLATFORM}" = "windows" ; then
    AC_DEFINE(BUILD_tls)
    AC_DEFINE(WINDOWS)
    CLEANFILES="pkgIndex.tcl *.lib *.dll *.exp *.ilk *.pdb vc*.pch"
else
    CLEANFILES="pkgIndex.tcl *.so"
fi
AC_SUBST(CLEANFILES)

#--------------------------------------------------------------------
# Choose which headers you need.  Extension authors should try very
# hard to only rely on the Tcl public header files.  Internal headers
# contain private data structures and are subject to change without
# notice.
# This MUST be called after TEA_LOAD_TCLCONFIG / TEA_LOAD_TKCONFIG
#--------------------------------------------------------------------

TEA_PUBLIC_TCL_HEADERS
#TEA_PRIVATE_TCL_HEADERS

#TEA_PUBLIC_TK_HEADERS
#TEA_PRIVATE_TK_HEADERS
#TEA_PATH_X

#--------------------------------------------------------------------
# Check whether --enable-threads or --disable-threads was given.
# This auto-enables if Tcl was compiled threaded.
#--------------------------------------------------------------------

TEA_ENABLE_THREADS

#--------------------------------------------------------------------
# The statement below defines a collection of symbols related to
# building as a shared library instead of a static library.
#--------------------------------------------------------------------

TEA_ENABLE_SHARED

#--------------------------------------------------------------------
# This macro figures out what flags to use with the compiler/linker
# when building shared/static debug/optimized objects.  This information
# can be taken from the tclConfig.sh file, but this figures it all out.
#--------------------------------------------------------------------

TEA_CONFIG_CFLAGS

#--------------------------------------------------------------------
# Set the default compiler switches based on the --enable-symbols option.
#--------------------------------------------------------------------

TEA_ENABLE_SYMBOLS

#--------------------------------------------------------------------
# Everyone should be linking against the Tcl stub library.  If you
# can't for some reason, remove this definition.  If you aren't using
# stubs, you also need to modify the SHLIB_LD_LIBS setting below to
# link against the non-stubbed Tcl library.  Add Tk too if necessary.
#--------------------------------------------------------------------

AC_DEFINE(USE_TCL_STUBS)
#AC_DEFINE(USE_TK_STUBS)

#--------------------------------------------------------------------
# This macro generates a line to use when building a library.  It
# depends on values set by the TEA_ENABLE_SHARED, TEA_ENABLE_SYMBOLS,
# and TEA_LOAD_TCLCONFIG macros above.
#--------------------------------------------------------------------

TEA_MAKE_LIB

#--------------------------------------------------------------------
# If the variable OPENSSL is set, we will build with the OpenSSL
# libraries.  If it is not set, then we will use RSA BSAFE SSL-C
# libraries instead of the default OpenSSL libaries.
#--------------------------------------------------------------------

OPENSSL="1"

TCLTLS_SSL_OPENSSL

#--------------------------------------------------------------------
# Shared libraries and static libraries have different names.
# Also, windows libraries and unix libraries have different names.
# For the OpenSSL version, I chose to use the same library names that
# OpenSSL uses as its default names.
#--------------------------------------------------------------------

if test "${TEA_PLATFORM}" = "windows" ; then
    if test "$GCC" = "yes"; then
	TEA_ADD_LIBS([-L${SSL_LIB_DIR_NATIVE}])
    else
	TEA_ADD_LIBS([-libpath:${SSL_LIB_DIR_NATIVE}])
    fi
    if test -n "${OPENSSL}"; then
        TEA_ADD_LIBS([libcrypto.lib libssl.lib])
    else
        TEA_ADD_LIBS([sslc32.lib])
else
    # Subst runtime dir here, use -R and -L where necessary. [Bug 1742859]
    LIB_RUNTIME_DIR=${SSL_LIB_DIR}
    eval "LD_SEARCH_FLAGS=\"${LD_SEARCH_FLAGS}\""
    if test -n "${OPENSSL}"; then
	TEA_ADD_LIBS([${LD_SEARCH_FLAGS} -L${SSL_LIB_DIR} -lssl -lcrypto ${GCCPATH} ${GCCLIB}])
    else
	TEA_ADD_LIBS([${LD_SEARCH_FLAGS} -L${SSL_LIB_DIR} -lsslc])
    fi
fi

#--------------------------------------------------------------------
# Determine the name of the tclsh and/or wish executables in the
# Tcl and Tk build directories or the location they were installed
# into. These paths are used to support running test cases only,
# the Makefile should not be making use of these paths to generate
# a pkgIndex.tcl file or anything else at extension build time.
#--------------------------------------------------------------------

TEA_PROG_TCLSH
#TEA_PROG_WISH

#--------------------------------------------------------------------
# Setup a *Config.sh.in configuration file.
#--------------------------------------------------------------------

#TEA_EXPORT_CONFIG([tls])
#AC_SUBST(SAMPLE_VAR)


#--------------------------------------------------------------------
# Custom
#--------------------------------------------------------------------

dnl Enable support for building the same library every time
tcltls_deterministic='false'
AC_ARG_ENABLE([deterministic], AS_HELP_STRING([--enable-deterministic], [enable deterministic parameters]), [
	if test "$enableval" = "yes"; then
		tcltls_deterministic='true'
	fi
])
if test "$tcltls_deterministic" = 'true'; then
	GEN_DH_PARAMS_ARGS='fallback'
else
	GEN_DH_PARAMS_ARGS=''
fi


dnl Enable support for specifying pre-computed DH params size
AC_ARG_WITH([builtin-dh-params-size], AS_HELP_STRING([--with-builtin-dh-params-size=<bits>], [specify the size of the built-in, precomputed, DH params]), [
	AS_CASE([$withval],
		[2048|4096|8192],,
		[
			AC_MSG_ERROR([Unsupported DH params size: $withval])
		]
	)
	GEN_DH_PARAMS_ARGS="${GEN_DH_PARAMS_ARGS} bits=$withval"
])
AC_SUBST(GEN_DH_PARAMS_ARGS)


dnl Determine if we have been asked to use a fast path if possible
tcltls_ssl_fastpath='no'
AC_ARG_ENABLE([ssl-fastpath], AS_HELP_STRING([--enable-ssl-fastpath], [enable using the underlying file descriptor for talking directly to the SSL library]), [
	if test "$enableval" = 'yes'; then
		tcltls_ssl_fastpath='yes'
	else
		tcltls_ssl_fastpath='no'
	fi
])

if test "$tcltls_ssl_fastpath" = 'yes'; then
	AC_DEFINE(TCLTLS_SSL_USE_FASTPATH, [1], [Define this to enable using the underlying file descriptor for talking directly to the SSL library])
fi


dnl Determine if we have been asked to statically link to the SSL library
TCLEXT_TLS_STATIC_SSL='no'
AC_ARG_ENABLE([static-ssl], AS_HELP_STRING([--enable-static-ssl], [enable statically linking to the specified SSL library]), [
	if test "$enableval" = 'yes'; then
		TCLEXT_TLS_STATIC_SSL='yes'
	fi
])


dnl Enable hardening
tcltls_enable_hardening='auto'
AC_ARG_ENABLE([hardening], AS_HELP_STRING([--disable-hardening], [disable hardening attempts]), [
	tcltls_enable_hardening="$enableval"
])
if test "$tcltls_enable_hardening" = 'auto'; then
	tcltls_enable_hardening='true'
	if test "$TCLEXT_BUILD" = 'static'; then
		tcltls_enable_hardening='false'
	fi
elif test "$tcltls_enable_hardening" = 'yes'; then
	tcltls_enable_hardening='true'
else
	tcltls_enable_hardening='false'
fi
if test "$tcltls_enable_hardening" = 'true'; then
	AX_CHECK_COMPILE_FLAG([-fstack-protector-all], [CFLAGS="$CFLAGS -fstack-protector-all"])
	AX_CHECK_COMPILE_FLAG([-fno-strict-overflow], [CFLAGS="$CFLAGS -fno-strict-overflow"])
	AC_DEFINE([_FORTIFY_SOURCE], [2], [Enable fortification])
fi


#--------------------------------------------------------------------
# Specify files to substitute AC variables in. You may alternatively
# have a special pkgIndex.tcl.in or other files which require
# substituting the AC variables in. Include these here.
#--------------------------------------------------------------------

#AC_CONFIG_FILES([Makefile pkgIndex.tcl])
#AC_CONFIG_FILES([tlsConfig.sh])

#--------------------------------------------------------------------
# Finally, substitute all of the various values into the files
# specified with AC_CONFIG_FILES.
#--------------------------------------------------------------------

AC_OUTPUT([Makefile pkgIndex.tcl])
