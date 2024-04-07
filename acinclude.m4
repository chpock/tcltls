#
# Include the TEA standard macro set
#

builtin(include,tclconfig/tcl.m4)

#
# Add here whatever m4 macros you want to define for your package
#

AC_DEFUN([TCLTLS_SSL_OPENSSL], [
	AC_CHECK_TOOL([PKG_CONFIG], [pkg-config])

	dnl Disable support for TLS 1.0 protocol
	AC_ARG_ENABLE([tls1], AS_HELP_STRING([--disable-tls1], [disable TLS1 protocol]), [
		if test "${enableval}" = "no"; then
			AC_DEFINE([NO_TLS1], [1], [Disable TLS1 protocol])
			AC_MSG_CHECKING([for disable TLS1 protocol])
			AC_MSG_RESULT([yes])
		fi
	])

	dnl Disable support for TLS 1.1 protocol
	AC_ARG_ENABLE([tls1_1], AS_HELP_STRING([--disable-tls1_1], [disable TLS1.1 protocol]), [
		if test "${enableval}" = "no"; then
			AC_DEFINE([NO_TLS1_1], [1], [Disable TLS1.1 protocol])
			AC_MSG_CHECKING([for disable TLS1.1 protocol])
			AC_MSG_RESULT([yes])
		fi
	])

	dnl Disable support for TLS 1.2 protocol
	AC_ARG_ENABLE([tls1_2], AS_HELP_STRING([--disable-tls1_2], [disable TLS1.2 protocol]), [
		if test "${enableval}" = "no"; then
			AC_DEFINE([NO_TLS1_2], [1], [Disable TLS1.2 protocol])
			AC_MSG_CHECKING([for disable TLS1.2 protocol])
			AC_MSG_RESULT([yes])
		fi
	])

	dnl Disable support for TLS 1.3 protocol
	AC_ARG_ENABLE([tls1_3], AS_HELP_STRING([--disable-tls1_3], [disable TLS1.3 protocol]), [
		if test "${enableval}" = "no"; then
			AC_DEFINE([NO_TLS1_3], [1], [Disable TLS1.3 protocol])
			AC_MSG_CHECKING([for disable TLS1.3 protocol])
			AC_MSG_RESULT([yes])
		fi
	])


	dnl Determine if we have been asked to use a fast path if possible
	AC_ARG_ENABLE([ssl-fastpath], AS_HELP_STRING([--enable-ssl-fastpath],
		[enable using the underlying file descriptor for talking directly to the SSL library]), [
		tcltls_ssl_fastpath="$enableval"
	], [
		tcltls_ssl_fastpath='no'
	])
	if test "$tcltls_ssl_fastpath" = 'yes'; then
		AC_DEFINE(TCLTLS_SSL_USE_FASTPATH, [1], [Enable SSL library direct use of the underlying file descriptor])
	fi
	AC_MSG_CHECKING([for fast path])
	AC_MSG_RESULT([$tcltls_ssl_fastpath])


	dnl Enable hardening
	AC_ARG_ENABLE([hardening], AS_HELP_STRING([--enable-hardening], [enable hardening attempts]), [
		tcltls_enable_hardening="$enableval"
	], [
		tcltls_enable_hardening='yes'
	])
	if test "$tcltls_enable_hardening" = 'yes'; then
		if test "$GCC" = 'yes' -o "$CC" = 'clang'; then
			TEA_ADD_CFLAGS([-fstack-protector-all])
			TEA_ADD_CFLAGS([-fno-strict-overflow])
			AC_DEFINE([_FORTIFY_SOURCE], [2], [Enable fortification])
		fi
	fi
	AC_MSG_CHECKING([for enable hardening])
	AC_MSG_RESULT([$tcltls_enable_hardening])


	dnl Determine if we have been asked to statically link to the SSL library
	AC_ARG_ENABLE([static-ssl], AS_HELP_STRING([--enable-static-ssl], [enable static linking to the SSL library]), [
		TCLEXT_TLS_STATIC_SSL="$enableval"
	], [
		TCLEXT_TLS_STATIC_SSL='no'
	])
	AC_MSG_CHECKING([for static linking of SSL libraries])
	AC_MSG_RESULT([$TCLEXT_TLS_STATIC_SSL])


	dnl Set SSL files root path
	AC_ARG_WITH([openssl-dir],
		AS_HELP_STRING([--with-openssl-dir=<dir>],
			[path to root directory of OpenSSL or LibreSSL installation]
		), [
			openssldir="$withval"
		], [
			openssldir=''
		]
	)
	AC_MSG_CHECKING([for OpenSSL directory])
	AC_MSG_RESULT($openssldir)

	dnl Set SSL include files path
	AC_ARG_WITH([openssl-includedir],
		AS_HELP_STRING([--with-openssl-includedir=<dir>],
			[path to include directory of OpenSSL or LibreSSL installation]
		), [
			opensslincludedir="$withval"
		], [
			if test ! -z "$openssldir"; then
				opensslincludedir="${openssldir}/include"
			else
				opensslincludedir=''
			fi
		]
	)
	AC_MSG_CHECKING([for OpenSSL include directory])
	AC_MSG_RESULT($opensslincludedir)

	dnl Set SSL files root path
	AC_ARG_WITH([wolfssl-dir],
		AS_HELP_STRING([--with-wolfssl-dir=<dir>],
			[path to root directory of wolfSSL installation]
		), [
			wolfssldir="$withval"
		], [
			wolfssldir=''
		]
	)
	AC_MSG_CHECKING([for wolfSSL directory])
	AC_MSG_RESULT($wolfssldir)

	dnl Set SSL include files path
	AC_ARG_WITH([wolfssl-includedir],
		AS_HELP_STRING([--with-wolfssl-includedir=<dir>],
			[path to include directory of wolfSSL installation]
		), [
			wolfsslincludedir="$withval"
		], [
			if test ! -z "$wolfssldir"; then
				wolfsslincludedir="${wolfssldir}/include"
			else
				wolfsslincludedir=''
			fi
		]
	)
	AC_MSG_CHECKING([for wolfSSL include directory])
	AC_MSG_RESULT($wolfsslincludedir)

	dnl Set SSL include vars
	if test ! -z "$wolfsslincludedir"; then
		if test -f "$wolfsslincludedir/wolfssl/openssl/ssl.h"; then
			TCLTLS_SSL_CFLAGS="-I$wolfsslincludedir"
			TCLTLS_SSL_INCLUDES="-I$wolfsslincludedir"
			AC_MSG_CHECKING([for ssl.h])
			AC_MSG_RESULT([yes])
			use_wolfssl=yes
		else
			AC_MSG_CHECKING([for ssl.h])
			AC_MSG_RESULT([no])
			AC_MSG_ERROR([Unable to locate ssl.h])
		fi
	elif test ! -z "$opensslincludedir"; then
		if test -f "$opensslincludedir/openssl/ssl.h"; then
			TCLTLS_SSL_CFLAGS="-I$opensslincludedir"
			TCLTLS_SSL_INCLUDES="-I$opensslincludedir"
			AC_MSG_CHECKING([for ssl.h])
			AC_MSG_RESULT([yes])
		else
			AC_MSG_CHECKING([for ssl.h])
			AC_MSG_RESULT([no])
			AC_MSG_ERROR([Unable to locate ssl.h])
		fi
	fi

	dnl Set SSL lib files path
	AC_ARG_WITH([openssl-libdir],
		AS_HELP_STRING([--with-openssl-libdir=<dir>],
			[path to lib directory of OpenSSL or LibreSSL installation]
		), [
			openssllibdir="$withval"
		], [
			if test ! -z "$openssldir"; then
				if test "$do64bit" == 'yes'; then
					openssllibdir="$openssldir/lib64"
				else
					openssllibdir="$openssldir/lib"
				fi
			else
				openssllibdir=''
			fi
		]
	)
	AC_MSG_CHECKING([for OpenSSL lib directory])
	AC_MSG_RESULT($openssllibdir)

	dnl Set SSL lib files path
	AC_ARG_WITH([wolfssl-libdir],
		AS_HELP_STRING([--with-wolfssl-libdir=<dir>],
			[path to lib directory of wolfSSL installation]
		), [
			wolfssllibdir="$withval"
		], [
			if test ! -z "$wolfssldir"; then
				if test "$do64bit" == 'yes'; then
					woldssllibdir="$wolfssldir/lib64"
				else
					wolfssllibdir="$wolfssldir/lib"
				fi
			else
				wolfssllibdir=''
			fi
		]
	)
	AC_MSG_CHECKING([for wolfSSL lib directory])
	AC_MSG_RESULT($wolfssllibdir)

	dnl Set SSL lib vars
	if test ! -z "$wolfssllibdir"; then
		if test "${TCLEXT_TLS_STATIC_SSL}" == 'no'; then
			if test -f "$wolfssllibdir/libwolfssl${SHLIB_SUFFIX}"; then
				TCLTLS_SSL_LIBS="-L$wolfssllibdir -lwolfssl"
			else
				AC_MSG_ERROR([Unable to locate libwolfssl${SHLIB_SUFFIX}])
			fi
		else
			if test -f "$wolfssllibdir/libwolfssl.a"; then
				TCLTLS_SSL_LIBS="-L$wolfssllibdir -lwolfssl"
			else
				AC_MSG_ERROR([Unable to locate libwolfssl.a])
			fi
		fi
	elif test ! -z "$openssllibdir"; then
		if test -f "$openssllibdir/libssl${SHLIB_SUFFIX}"; then
			if test "${TCLEXT_TLS_STATIC_SSL}" == 'no'; then
				TCLTLS_SSL_LIBS="-L$openssllibdir -lcrypto -lssl"
			#else
				# Linux and Solaris
				#TCLTLS_SSL_LIBS="-Wl,-Bstatic `$PKG_CONFIG --static --libs crypto ssl` -Wl,-Bdynamic"
				# HPUX
				# -Wl,-a,archive ... -Wl,-a,shared_archive
			fi
		else
			AC_MSG_ERROR([Unable to locate libssl${SHLIB_SUFFIX}])
		fi
	fi

	dnl Set location of pkgconfig files
	AC_ARG_WITH([openssl-pkgconfig],
		AS_HELP_STRING([--with-openssl-pkgconfig=<dir>],
			[path to pkgconfigdir directory for OpenSSL or LibreSSL]
		), [
			opensslpkgconfigdir="$withval"
		], [
			if test -d ${libdir}/../pkgconfig; then
				opensslpkgconfigdir="$libdir/../pkgconfig"
			else
				opensslpkgconfigdir=''
			fi
		]
	)
	AC_MSG_CHECKING([for OpenSSL pkgconfig])
	AC_MSG_RESULT($opensslpkgconfigdir)

	dnl Set location of pkgconfig files
	AC_ARG_WITH([wolfssl-pkgconfig],
		AS_HELP_STRING([--with-wolfssl-pkgconfig=<dir>],
			[path to pkgconfigdir directory for wolfSSL]
		), [
			wolfsslpkgconfigdir="$withval"
		], [
			if test -d ${libdir}/../pkgconfig; then
				wolfsslpkgconfigdir="$libdir/../pkgconfig"
			else
				wolfsslpkgconfigdir=''
			fi
		]
	)
	AC_MSG_CHECKING([for wolfSSL pkgconfig])
	AC_MSG_RESULT($wolfsslpkgconfigdir)


	# Use Package Config tool to get config
	pkgConfigExtraArgs=''
	if test "${SHARED_BUILD}" == 0 -o "$TCLEXT_TLS_STATIC_SSL" = 'yes'; then
		pkgConfigExtraArgs='--static'
	fi

	dnl Use pkg-config to find the libraries
	if test -n "${PKG_CONFIG}"; then
		dnl Temporarily update PKG_CONFIG_PATH
		PKG_CONFIG_PATH_SAVE="${PKG_CONFIG_PATH}"
		if test -n "${wolfsslpkgconfigdir}"; then
			if ! test -f "${wolfsslpkgconfigdir}/wolfssl.pc"; then
				AC_MSG_ERROR([Unable to locate ${wolfsslpkgconfigdir}/wolfssl.pc])
			fi

			PKG_CONFIG_PATH="${wolfsslpkgconfigdir}:${PKG_CONFIG_PATH}"
			export PKG_CONFIG_PATH
			use_wolfssl=yes
		elif test -n "${opensslpkgconfigdir}"; then
			if ! test -f "${opensslpkgconfigdir}/openssl.pc"; then
				AC_MSG_ERROR([Unable to locate ${opensslpkgconfigdir}/openssl.pc])
			fi

			PKG_CONFIG_PATH="${opensslpkgconfigdir}:${PKG_CONFIG_PATH}"
			export PKG_CONFIG_PATH
		fi
		if test -z "$use_wolfssl"; then
			if test -z "$TCLTLS_SSL_LIBS"; then
				TCLTLS_SSL_LIBS="`"${PKG_CONFIG}" openssl --libs $pkgConfigExtraArgs`" || AC_MSG_ERROR([Unable to get OpenSSL Configuration])
			fi
			if test -z "$TCLTLS_SSL_CFLAGS"; then
				TCLTLS_SSL_CFLAGS="`"${PKG_CONFIG}" openssl --cflags-only-other $pkgConfigExtraArgs`" || AC_MSG_ERROR([Unable to get OpenSSL Configuration])
			fi
			if test -z "$TCLTLS_SSL_INCLUDES"; then
				TCLTLS_SSL_INCLUDES="`"${PKG_CONFIG}" openssl --cflags-only-I $pkgConfigExtraArgs`" || AC_MSG_ERROR([Unable to get OpenSSL Configuration])
			fi
		else
			if test -z "$TCLTLS_SSL_LIBS"; then
				TCLTLS_SSL_LIBS="`"${PKG_CONFIG}" wolfssl --libs $pkgConfigExtraArgs`" || AC_MSG_ERROR([Unable to get wolfSSL Configuration])
			fi
			if test -z "$TCLTLS_SSL_CFLAGS"; then
				TCLTLS_SSL_CFLAGS="`"${PKG_CONFIG}" wolfssl --cflags-only-other $pkgConfigExtraArgs`" || AC_MSG_ERROR([Unable to get wolfSSL Configuration])
			fi
			if test -z "$TCLTLS_SSL_INCLUDES"; then
				TCLTLS_SSL_INCLUDES="`"${PKG_CONFIG}" wolfssl --cflags-only-I $pkgConfigExtraArgs`" || AC_MSG_ERROR([Unable to get wolfSSL Configuration])
			fi
		fi
		PKG_CONFIG_PATH="${PKG_CONFIG_PATH_SAVE}"
	fi


	dnl Fallback settings for OpenSSL includes and libs
	if test -z "$TCLTLS_SSL_LIBS"; then
		TCLTLS_SSL_LIBS="-lcrypto -lssl"
	fi
	if test -z "$TCLTLS_SSL_CFLAGS"; then
		TCLTLS_SSL_CFLAGS=""
	fi
	if test -z "$TCLTLS_SSL_INCLUDES"; then
		if test -f /usr/include/openssl/ssl.h; then
			TCLTLS_SSL_INCLUDES="-I/usr/include"
		fi
	fi
	if test "$use_wolfssl" == "yes"; then
		TCLTLS_SSL_CFLAGS="${TCLTLS_SSL_CFLAGS} -DUSE_WOLFSSL"
	else
		TCLTLS_SSL_CFLAGS="${TCLTLS_SSL_CFLAGS} -DUSE_OPENSSL"
	fi

	dnl Include config variables in --help list and make available to be substituted via AC_SUBST.
	AC_ARG_VAR([TCLTLS_SSL_CFLAGS], [C compiler flags for OpenSSL, LibreSSL or wolfSSL])
	AC_ARG_VAR([TCLTLS_SSL_INCLUDES], [C compiler include paths for OpenSSL, LibreSSL or wolfSSL])
	AC_ARG_VAR([TCLTLS_SSL_LIBS], [libraries to pass to the linker for OpenSSL, LibreSSL or wolfSSL])
])
