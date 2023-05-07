#
# Include the TEA standard macro set
#

builtin(include,tclconfig/tcl.m4)

#
# Add here whatever m4 macros you want to define for your package
#

dnl $1 = Description to show user
dnl $2 = Libraries to link to
dnl $3 = Variable to update (optional; default LIBS)
dnl $4 = Action to run if found
dnl $5 = Action to run if not found
AC_DEFUN([SHOBJ_DO_STATIC_LINK_LIB], [
        ifelse($3, [], [
                define([VAR_TO_UPDATE], [LIBS])
        ], [
                define([VAR_TO_UPDATE], [$3])
        ])

	AC_MSG_CHECKING([for how to statically link to $1])

	trylink_ADD_LDFLAGS=''
	for arg in $VAR_TO_UPDATE; do
		case "${arg}" in
			-L*)
				trylink_ADD_LDFLAGS="${arg}"
				;;
		esac
	done

	SAVELIBS="$LIBS"
	staticlib=""
	found="0"
	dnl HP/UX uses -Wl,-a,archive ... -Wl,-a,shared_archive
	dnl Linux and Solaris us -Wl,-Bstatic ... -Wl,-Bdynamic
	AC_LANG_PUSH([C])
	for trylink in "-Wl,-a,archive $2 -Wl,-a,shared_archive" "-Wl,-Bstatic $2 -Wl,-Bdynamic" "$2"; do
		if echo " ${LDFLAGS} " | grep ' -static ' >/dev/null; then
			if test "${trylink}" != "$2"; then
				continue
			fi
		fi

		LIBS="${SAVELIBS} ${trylink_ADD_LDFLAGS} ${trylink}"

		AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])], [
			staticlib="${trylink}"
			found="1"

			break
		])
	done
	AC_LANG_POP([C])
	LIBS="${SAVELIBS}"

	if test "${found}" = "1"; then
		new_RESULT=''
		SAVERESULT="$VAR_TO_UPDATE"
		for lib in ${SAVERESULT}; do
			addlib='1'
			for removelib in $2; do
				if test "${lib}" = "${removelib}"; then
					addlib='0'
					break
				fi
			done

			if test "$addlib" = '1'; then
				new_RESULT="${new_RESULT} ${lib}"
			fi
		done
		VAR_TO_UPDATE="${new_RESULT} ${staticlib}"

		AC_MSG_RESULT([${staticlib}])

		$4
	else
		AC_MSG_RESULT([cant])

		$5
	fi
])

AC_DEFUN([TCLTLS_SSL_OPENSSL], [
	openssldir=''
	opensslpkgconfigdir=''
	AC_ARG_WITH([openssl-dir],
		AS_HELP_STRING(
			[--with-openssl-dir=<dir>],
			[path to root directory of OpenSSL or LibreSSL installation]
		), [
			openssldir="$withval"
		]
	)
	AC_ARG_WITH([openssl-pkgconfig],
		AS_HELP_STRING(
			[--with-openssl-pkgconfig=<dir>],
			[path to root directory of OpenSSL or LibreSSL pkgconfigdir]
		), [
			opensslpkgconfigdir="$withval"
		]
	)

	if test -n "$openssldir"; then
		if test -e "$openssldir/libssl.$SHOBJEXT"; then
			TCLTLS_SSL_LIBS="-L$openssldir -lssl -lcrypto"
			openssldir="`AS_DIRNAME(["$openssldir"])`"
		else
			TCLTLS_SSL_LIBS="-L$openssldir/lib -lssl -lcrypto"
		fi
		TCLTLS_SSL_CFLAGS="-I$openssldir/include"
		TCLTLS_SSL_CPPFLAGS="-I$openssldir/include"
	fi

	pkgConfigExtraArgs=''
	if test "${SHARED_BUILD}" != "1" -o "$TCLEXT_TLS_STATIC_SSL" = 'yes'; then
		pkgConfigExtraArgs='--static'
	fi

	dnl Use pkg-config to find the libraries
	dnl Temporarily update PKG_CONFIG_PATH
	PKG_CONFIG_PATH_SAVE="${PKG_CONFIG_PATH}"
	if test -n "${opensslpkgconfigdir}"; then
		if ! test -f "${opensslpkgconfigdir}/openssl.pc"; then
			AC_MSG_ERROR([Unable to locate ${opensslpkgconfigdir}/openssl.pc])
		fi

		PKG_CONFIG_PATH="${opensslpkgconfigdir}${PATH_SEPARATOR}${PKG_CONFIG_PATH}"
		export PKG_CONFIG_PATH
	fi

	AC_ARG_VAR([TCLTLS_SSL_LIBS], [libraries to pass to the linker for OpenSSL or LibreSSL])
	AC_ARG_VAR([TCLTLS_SSL_CFLAGS], [C compiler flags for OpenSSL or LibreSSL])
	AC_ARG_VAR([TCLTLS_SSL_CPPFLAGS], [C preprocessor flags for OpenSSL or LibreSSL])
	if test -z "$TCLTLS_SSL_LIBS"; then
		TCLTLS_SSL_LIBS="`"${PKGCONFIG}" openssl --libs $pkgConfigExtraArgs`" || AC_MSG_ERROR([Unable to get OpenSSL Configuration])
	fi
	if test -z "$TCLTLS_SSL_CFLAGS"; then
		TCLTLS_SSL_CFLAGS="`"${PKGCONFIG}" openssl --cflags-only-other $pkgConfigExtraArgs`" || AC_MSG_ERROR([Unable to get OpenSSL Configuration])
	fi
	if test -z "$TCLTLS_SSL_CPPFLAGS"; then
		TCLTLS_SSL_CPPFLAGS="`"${PKGCONFIG}" openssl --cflags-only-I $pkgConfigExtraArgs`" || AC_MSG_ERROR([Unable to get OpenSSL Configuration])
	fi
	PKG_CONFIG_PATH="${PKG_CONFIG_PATH_SAVE}"

	if test "${SHARED_BUILD}" != "1"; then
		dnl If we are doing a static build, save the linker flags for other programs to consume
		rm -f tcltls.${AREXT}.linkadd
		AS_ECHO(["$TCLTLS_SSL_LIBS"]) > tcltls.${AREXT}.linkadd
	fi

	dnl If we have been asked to statically link to the SSL library, specifically tell the linker to do so
	if test "$TCLEXT_TLS_STATIC_SSL" = 'yes'; then
		dnl Don't bother doing this if we aren't actually doing the runtime linking
		if test "${SHARED_BUILD}" = "1"; then
			dnl Split the libraries into SSL and non-SSL libraries
			new_TCLTLS_SSL_LIBS_normal=''
			new_TCLTLS_SSL_LIBS_static=''
			for arg in $TCLTLS_SSL_LIBS; do
				case "${arg}" in
					-L*)
						new_TCLTLS_SSL_LIBS_normal="${new_TCLTLS_SSL_LIBS_normal} ${arg}"
						new_TCLTLS_SSL_LIBS_static="${new_TCLTLS_SSL_LIBS_static} ${arg}"
						;;
					-ldl|-lrt|-lc|-lpthread|-lm|-lcrypt|-lidn|-lresolv|-lgcc|-lgcc_s)
						new_TCLTLS_SSL_LIBS_normal="${new_TCLTLS_SSL_LIBS_normal} ${arg}"
						;;
					-l*)
						new_TCLTLS_SSL_LIBS_static="${new_TCLTLS_SSL_LIBS_static} ${arg}"
						;;
					*)
						new_TCLTLS_SSL_LIBS_normal="${new_TCLTLS_SSL_LIBS_normal} ${arg}"
						;;
				esac
			done
			SHOBJ_DO_STATIC_LINK_LIB([OpenSSL], [$new_TCLTLS_SSL_LIBS_static], [new_TCLTLS_SSL_LIBS_static])
			TCLTLS_SSL_LIBS="${new_TCLTLS_SSL_LIBS_normal} ${new_TCLTLS_SSL_LIBS_static}"
		fi
	fi
])
