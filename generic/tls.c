/*
 * Copyright (C) 1997-1999 Matt Newman <matt@novadigm.com>
 * some modifications:
 *	Copyright (C) 2000 Ajuba Solutions
 *	Copyright (C) 2002 ActiveState Corporation
 *	Copyright (C) 2004 Starfish Systems
 *	Copyright (C) 2023 Brian O'Hagan
 *
 * TLS (aka SSL) Channel - can be layered on any bi-directional
 * Tcl_Channel (Note: Requires Trf Core Patch)
 *
 * This was built (almost) from scratch based upon observation of
 * OpenSSL 0.9.2B
 *
 * Addition credit is due for Andreas Kupries (a.kupries@westend.com), for
 * providing the Tcl_ReplaceChannel mechanism and working closely with me
 * to enhance it to support full fileevent semantics.
 *
 * Also work done by the follow people provided the impetus to do this "right":
 *	tclSSL (Colin McCormack, Shared Technology)
 *	SSLtcl (Peter Antman)
 *
 */

#include "tlsInt.h"
#include "tclOpts.h"
#include <stdio.h>
#include <stdlib.h>
#include "tlsUuid.h"

/* Min OpenSSL version */
#if OPENSSL_VERSION_NUMBER < 0x10101000L
#error "Only OpenSSL v1.1.1 or later is supported"
#endif

/*
 * External functions
 */

/*
 * Forward declarations
 */

#define F2N(key, dsp) \
	(((key) == NULL) ? (char *)NULL : \
		Tcl_TranslateFileName(interp, (key), (dsp)))

static SSL_CTX *CTX_Init(State *statePtr, int isServer, int proto, char *key,
		char *certfile, unsigned char *key_asn1, unsigned char *cert_asn1,
		int key_asn1_len, int cert_asn1_len, char *CAdir, char *CAfile,
		char *ciphers, char *DHparams);

static int	TlsLibInit(int uninitialize);

#define TLS_PROTO_SSL2		0x01
#define TLS_PROTO_SSL3		0x02
#define TLS_PROTO_TLS1		0x04
#define TLS_PROTO_TLS1_1	0x08
#define TLS_PROTO_TLS1_2	0x10
#define TLS_PROTO_TLS1_3	0x20
#define ENABLED(flag, mask)	(((flag) & (mask)) == (mask))

/*
 * We lose the tcl password callback when we use the RSA BSAFE SSL-C 1.1.2
 * libraries instead of the current OpenSSL libraries.
 */

#ifdef BSAFE
#define PRE_OPENSSL_0_9_4 1
#endif

/*
 * Pre OpenSSL 0.9.4 Compat
 */

#ifndef STACK_OF
#define STACK_OF(x)			STACK
#define sk_SSL_CIPHER_num(sk)		sk_num((sk))
#define sk_SSL_CIPHER_value( sk, index)	(SSL_CIPHER*)sk_value((sk), (index))
#endif

/*
 * Thread-Safe TLS Code
 */

#ifdef TCL_THREADS
#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>

#ifdef OPENSSL_THREADS
#include <openssl/crypto.h>

/*
 * Threaded operation requires locking callbacks
 * Based from /crypto/cryptlib.c of OpenSSL and NSOpenSSL.
 */

static Tcl_Mutex *locks = NULL;
static int locksCount = 0;
static Tcl_Mutex init_mx;

void CryptoThreadLockCallback(
    int mode,
    int n,
    TCL_UNUSED(const char *),
    TCL_UNUSED(int))
{
	if (mode & CRYPTO_LOCK) {
		/* This debugging is turned off by default -- it's too noisy. */
		/* dprintf("Called to lock (n=%i of %i)", n, locksCount); */
		Tcl_MutexLock(&locks[n]);
	} else {
		/* dprintf("Called to unlock (n=%i of %i)", n, locksCount); */
		Tcl_MutexUnlock(&locks[n]);
	}

	/* dprintf("Returning"); */

	return;
}

unsigned long CryptoThreadIdCallback(void) {
	unsigned long ret;

	dprintf("Called");

	ret = (unsigned long) Tcl_GetCurrentThread();

	dprintf("Returning %lu", ret);

	return(ret);
}
#endif /* OPENSSL_THREADS */
#endif /* TCL_THREADS */


/*
 *-------------------------------------------------------------------
 *
 * InfoCallback --
 *
 *	Monitors SSL connection process
 *
 * Results:
 *	None
 *
 * Side effects:
 *	Calls callback (if defined)
 *
 *-------------------------------------------------------------------
 */
static void
InfoCallback(const SSL *ssl, int where, int ret)
{
    State *statePtr = (State*)SSL_get_app_data((SSL *)ssl);
    Tcl_Interp *interp	= statePtr->interp;
    Tcl_Obj *cmdPtr;
    const char *major, *minor;

    dprintf("Called");

    if (statePtr->callback == (Tcl_Obj*)NULL)
	return;

    cmdPtr = Tcl_DuplicateObj(statePtr->callback);

#if 0
    if (where & SSL_CB_ALERT) {
	sev = SSL_alert_type_string_long(ret);
	if (strcmp( sev, "fatal")==0) {	/* Map to error */
	    Tls_Error(statePtr, SSL_ERROR(ssl, 0));
	    return;
	}
    }
#endif
    if (where & SSL_CB_HANDSHAKE_START) {
	major = "handshake";
	minor = "start";
    } else if (where & SSL_CB_HANDSHAKE_DONE) {
	major = "handshake";
	minor = "done";
    } else {
	if (where & SSL_CB_ALERT)		major = "alert";
	else if (where & SSL_ST_CONNECT)	major = "connect";
	else if (where & SSL_ST_ACCEPT)		major = "accept";
	else					major = "unknown";

	if (where & SSL_CB_READ)		minor = "read";
	else if (where & SSL_CB_WRITE)		minor = "write";
	else if (where & SSL_CB_LOOP)		minor = "loop";
	else if (where & SSL_CB_EXIT)		minor = "exit";
	else					minor = "unknown";
    }

    Tcl_ListObjAppendElement( interp, cmdPtr,
	    Tcl_NewStringObj( "info", -1));

    Tcl_ListObjAppendElement( interp, cmdPtr,
	    Tcl_NewStringObj( Tcl_GetChannelName(statePtr->self), -1) );

    Tcl_ListObjAppendElement( interp, cmdPtr,
	    Tcl_NewStringObj( major, -1) );

    Tcl_ListObjAppendElement( interp, cmdPtr,
	    Tcl_NewStringObj( minor, -1) );

    if (where & (SSL_CB_LOOP|SSL_CB_EXIT)) {
	Tcl_ListObjAppendElement( interp, cmdPtr,
	    Tcl_NewStringObj( SSL_state_string_long(ssl), -1) );
    } else if (where & SSL_CB_ALERT) {
	const char *cp = (char *)SSL_alert_desc_string_long(ret);

	Tcl_ListObjAppendElement( interp, cmdPtr,
	    Tcl_NewStringObj( cp, -1) );
    } else {
	Tcl_ListObjAppendElement( interp, cmdPtr,
	    Tcl_NewStringObj( SSL_state_string_long(ssl), -1) );
    }
    Tcl_Preserve((void *) interp);
    Tcl_Preserve((void *) statePtr);

    Tcl_IncrRefCount( cmdPtr);
    (void) Tcl_EvalObjEx(interp, cmdPtr, TCL_EVAL_GLOBAL);
    Tcl_DecrRefCount( cmdPtr);

    Tcl_Release((void *) statePtr);
    Tcl_Release((void *) interp);

}

/*
 *-------------------------------------------------------------------
 *
 * VerifyCallback --
 *
 *	Monitors SSL certificate validation process.
 *	This is called whenever a certificate is inspected
 *	or decided invalid.
 *
 * Results:
 *	A callback bound to the socket may return one of:
 *	    0			- the certificate is deemed invalid
 *	    1			- the certificate is deemed valid
 *	    empty string	- no change to certificate validation
 *
 * Side effects:
 *	The err field of the currently operative State is set
 *	  to a string describing the SSL negotiation failure reason
 *
 *-------------------------------------------------------------------
 */
static int
VerifyCallback(int ok, X509_STORE_CTX *ctx)
{
    Tcl_Obj *cmdPtr, *result;
    char *errStr, *string;
    Tcl_Size length;
    SSL   *ssl		= (SSL*)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    X509  *cert		= X509_STORE_CTX_get_current_cert(ctx);
    State *statePtr	= (State*)SSL_get_app_data(ssl);
    int depth		= X509_STORE_CTX_get_error_depth(ctx);
    int err		= X509_STORE_CTX_get_error(ctx);

    dprintf("Verify: %d", ok);

    if (!ok) {
	errStr = (char *)X509_verify_cert_error_string(err);
    } else {
	errStr = (char *)0;
    }

    if (statePtr->callback == NULL) {
	if (statePtr->vflags & SSL_VERIFY_FAIL_IF_NO_PEER_CERT) {
	    return ok;
	} else {
	    return 1;
	}
    }
    cmdPtr = Tcl_DuplicateObj(statePtr->callback);

    Tcl_ListObjAppendElement( statePtr->interp, cmdPtr,
	    Tcl_NewStringObj( "verify", -1));

    Tcl_ListObjAppendElement( statePtr->interp, cmdPtr,
	    Tcl_NewStringObj( Tcl_GetChannelName(statePtr->self), -1) );

    Tcl_ListObjAppendElement( statePtr->interp, cmdPtr,
	    Tcl_NewIntObj( depth) );

    Tcl_ListObjAppendElement( statePtr->interp, cmdPtr,
	    Tls_NewX509Obj( statePtr->interp, cert) );

    Tcl_ListObjAppendElement( statePtr->interp, cmdPtr,
	    Tcl_NewIntObj( ok) );

    Tcl_ListObjAppendElement( statePtr->interp, cmdPtr,
	    Tcl_NewStringObj( errStr ? errStr : "", -1) );

    Tcl_Preserve((void *) statePtr->interp);
    Tcl_Preserve((void *) statePtr);

    statePtr->flags |= TLS_TCL_CALLBACK;

    Tcl_IncrRefCount( cmdPtr);
    if (Tcl_EvalObjEx(statePtr->interp, cmdPtr, TCL_EVAL_GLOBAL) != TCL_OK) {
	/* It got an error - reject the certificate.		*/
	Tcl_BackgroundError( statePtr->interp);
	ok = 0;
    } else {
	result = Tcl_GetObjResult(statePtr->interp);
	string = Tcl_GetStringFromObj(result, &length);
	/* An empty result leaves verification unchanged.	*/
	if (string != NULL && length > 0) {
	    if (Tcl_GetIntFromObj(statePtr->interp, result, &ok) != TCL_OK) {
		Tcl_BackgroundError(statePtr->interp);
		ok = 0;
	    }
	}
    }
    Tcl_DecrRefCount( cmdPtr);

    statePtr->flags &= ~(TLS_TCL_CALLBACK);

    Tcl_Release((void *) statePtr);
    Tcl_Release((void *) statePtr->interp);

    return(ok);	/* By default, leave verification unchanged.	*/
}

/*
 *-------------------------------------------------------------------
 *
 * Tls_Error --
 *
 *	Calls callback with $fd and $msg - so the callback can decide
 *	what to do with errors.
 *
 * Side effects:
 *	The err field of the currently operative State is set
 *	  to a string describing the SSL negotiation failure reason
 *-------------------------------------------------------------------
 */
void
Tls_Error(State *statePtr, char *msg)
{
    Tcl_Obj *cmdPtr;

    dprintf("Called");

    if (msg && *msg) {
	Tcl_SetErrorCode(statePtr->interp, "SSL", msg, (char *)NULL);
    } else {
	msg = Tcl_GetString(Tcl_GetObjResult(statePtr->interp));
    }
    statePtr->err = msg;

    if (statePtr->callback == (Tcl_Obj*)NULL) {
	char buf[BUFSIZ];
	sprintf(buf, "SSL channel \"%s\": error: %s",
	    Tcl_GetChannelName(statePtr->self), msg);
	Tcl_SetResult( statePtr->interp, buf, TCL_VOLATILE);
	Tcl_BackgroundError( statePtr->interp);
	return;
    }
    cmdPtr = Tcl_DuplicateObj(statePtr->callback);

    Tcl_ListObjAppendElement(statePtr->interp, cmdPtr,
	    Tcl_NewStringObj("error", -1));

    Tcl_ListObjAppendElement(statePtr->interp, cmdPtr,
	    Tcl_NewStringObj(Tcl_GetChannelName(statePtr->self), -1));

    Tcl_ListObjAppendElement(statePtr->interp, cmdPtr,
	    Tcl_NewStringObj(msg, -1));

    Tcl_Preserve((void *) statePtr->interp);
    Tcl_Preserve((void *) statePtr);

    Tcl_IncrRefCount(cmdPtr);
    if (Tcl_EvalObjEx(statePtr->interp, cmdPtr, TCL_EVAL_GLOBAL) != TCL_OK) {
	Tcl_BackgroundError(statePtr->interp);
    }
    Tcl_DecrRefCount(cmdPtr);

    Tcl_Release((void *) statePtr);
    Tcl_Release((void *) statePtr->interp);
}

/*
 *-------------------------------------------------------------------
 *
 * PasswordCallback --
 *
 *	Called when a password is needed to unpack RSA and PEM keys.
 *	Evals any bound password script and returns the result as
 *	the password string.
 *-------------------------------------------------------------------
 */
#ifdef PRE_OPENSSL_0_9_4
/*
 * No way to handle user-data therefore no way without a global
 * variable to access the Tcl interpreter.
*/
static int
PasswordCallback(
    TCL_UNUSED(char *) /* buf */,
    TCL_UNUSED(int) /* size */,
    TCL_UNUSED(int) /* verify */)
{
    return -1;
}
#else
static int
PasswordCallback(
    char *buf,
    int size,
    TCL_UNUSED(int), /* verify */
    void *udata)
{
    State *statePtr	= (State *) udata;
    Tcl_Interp *interp	= statePtr->interp;
    Tcl_Obj *cmdPtr;
    int result;

    dprintf("Called");

    if (statePtr->password == NULL) {
	if (Tcl_EvalEx(interp, "tls::password", -1, TCL_EVAL_GLOBAL)
		== TCL_OK) {
	    const char *ret = Tcl_GetStringResult(interp);
	    strncpy(buf, ret, (size_t) size);
	    return (int)strlen(ret);
	} else {
	    return -1;
	}
    }

    cmdPtr = Tcl_DuplicateObj(statePtr->password);

    Tcl_Preserve((void *) statePtr->interp);
    Tcl_Preserve((void *) statePtr);

    Tcl_IncrRefCount(cmdPtr);
    result = Tcl_EvalObjEx(interp, cmdPtr, TCL_EVAL_GLOBAL);
    if (result != TCL_OK) {
	Tcl_BackgroundError(statePtr->interp);
    }
    Tcl_DecrRefCount(cmdPtr);

    Tcl_Release((void *) statePtr);
    Tcl_Release((void *) statePtr->interp);

    if (result == TCL_OK) {
	const char *ret = Tcl_GetStringResult(interp);
	strncpy(buf, ret, (size_t) size);
	return (int)strlen(ret);
    } else {
	return -1;
    }
}
#endif

/*
 *-------------------------------------------------------------------
 *
 * CiphersObjCmd -- list available ciphers
 *
 *	This procedure is invoked to process the "tls::ciphers" command
 *	to list available ciphers, based upon protocol selected.
 *
 * Results:
 *	A standard Tcl result list.
 *
 * Side effects:
 *	constructs and destroys SSL context (CTX)
 *
 *-------------------------------------------------------------------
 */
static const char *protocols[] = {
    "ssl2", "ssl3", "tls1", "tls1.1", "tls1.2", "tls1.3", NULL
};
enum protocol {
    TLS_SSL2, TLS_SSL3, TLS_TLS1, TLS_TLS1_1, TLS_TLS1_2, TLS_TLS1_3, TLS_NONE
};

static int
CiphersObjCmd(
    TCL_UNUSED(void *),
    Tcl_Interp *interp,
    int objc,
    Tcl_Obj	*const objv[])
{
    Tcl_Obj *objPtr = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    STACK_OF(SSL_CIPHER) *sk;
    const char *cp;
    char buf[BUFSIZ];
    int index, verbose = 0;

    dprintf("Called");

    if ((objc < 2) || (objc > 3)) {
	Tcl_WrongNumArgs(interp, 1, objv, "protocol ?verbose?");
	return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], protocols, "protocol", 0, &index) != TCL_OK) {
	return TCL_ERROR;
    }
    if ((objc > 2) && Tcl_GetBooleanFromObj(interp, objv[2], &verbose) != TCL_OK) {
	return TCL_ERROR;
    }
    switch ((enum protocol)index) {
    case TLS_SSL2:
	Tcl_AppendResult(interp, protocols[index], ": protocol not supported", (char *)NULL);
	return TCL_ERROR;
    case TLS_SSL3:
	Tcl_AppendResult(interp, protocols[index], ": protocol not supported", (char *)NULL);
	return TCL_ERROR;
    case TLS_TLS1:
#if defined(NO_TLS1) || defined(OPENSSL_NO_TLS1) || defined(OPENSSL_NO_TLS1_METHOD)
	Tcl_AppendResult(interp, protocols[index], ": protocol not supported", (char *)NULL);
	return TCL_ERROR;
#else
	ctx = SSL_CTX_new(TLSv1_method()); break;
#endif
    case TLS_TLS1_1:
#if defined(NO_TLS1_1) || defined(OPENSSL_NO_TLS1_1) || defined(OPENSSL_NO_TLS1_1_METHOD)
	Tcl_AppendResult(interp, protocols[index], ": protocol not supported", (char *)NULL);
	return TCL_ERROR;
#else
	ctx = SSL_CTX_new(TLSv1_1_method()); break;
#endif
    case TLS_TLS1_2:
#if defined(NO_TLS1_2) || defined(OPENSSL_NO_TLS1_2) || defined(OPENSSL_NO_TLS1_2_METHOD)
	Tcl_AppendResult(interp, protocols[index], ": protocol not supported", (char *)NULL);
	return TCL_ERROR;
#else
	ctx = SSL_CTX_new(TLSv1_2_method()); break;
#endif
    case TLS_TLS1_3:
#if defined(NO_TLS1_3) || defined(OPENSSL_NO_TLS1_3) || defined(OPENSSL_NO_TLS1_3_METHOD)
	Tcl_AppendResult(interp, protocols[index], ": protocol not supported", (char *)NULL);
	return TCL_ERROR;
#else
	ctx = SSL_CTX_new(TLS_method());
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
	break;
#endif
    default:
	break;
    }
    if (ctx == NULL) {
	Tcl_AppendResult(interp, GET_ERR_REASON(), (char *)NULL);
	return TCL_ERROR;
    }
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
	Tcl_AppendResult(interp, GET_ERR_REASON(), (char *)NULL);
	SSL_CTX_free(ctx);
	return TCL_ERROR;
    }
    objPtr = Tcl_NewListObj( 0, NULL);

    if (!verbose) {
	for (index = 0; ; index++) {
	    cp = (char*)SSL_get_cipher_list( ssl, index);
	    if (cp == NULL) break;
	    Tcl_ListObjAppendElement( interp, objPtr,
		Tcl_NewStringObj( cp, -1) );
	}
    } else {
	sk = SSL_get_ciphers(ssl);

	for (index = 0; index < sk_SSL_CIPHER_num(sk); index++) {
	    size_t i;
	    SSL_CIPHER_description( sk_SSL_CIPHER_value( sk, index),
				    buf, sizeof(buf));
	    for (i = strlen(buf) - 1; i ; i--) {
		if (buf[i] == ' ' || buf[i] == '\n' ||
		    buf[i] == '\r' || buf[i] == '\t') {
		    buf[i] = '\0';
		} else {
		    break;
		}
	    }
	    Tcl_ListObjAppendElement( interp, objPtr,
		Tcl_NewStringObj( buf, -1) );
	}
    }
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    Tcl_SetObjResult(interp, objPtr);
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * HandshakeObjCmd --
 *
 *	This command is used to verify whether the handshake is complete
 *	or not.
 *
 * Results:
 *	A standard Tcl result. 1 means handshake complete, 0 means pending.
 *
 * Side effects:
 *	May force SSL negotiation to take place.
 *
 *-------------------------------------------------------------------
 */

static int HandshakeObjCmd(
    TCL_UNUSED(void *),
    Tcl_Interp *interp,
    int objc,
    Tcl_Obj *const objv[])
{
    Tcl_Channel chan;        /* The channel to set a mode on. */
    State *statePtr;        /* client state for ssl socket */
    const char *errStr = NULL;
    int ret = 1;
    int err = 0;

    dprintf("Called");

    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "channel");
	return(TCL_ERROR);
    }

    chan = Tcl_GetChannel(interp, Tcl_GetString(objv[1]), NULL);
    if (chan == (Tcl_Channel) NULL) {
	return(TCL_ERROR);
    }

    /* Make sure to operate on the topmost channel */
    chan = Tcl_GetTopChannel(chan);
    if (Tcl_GetChannelType(chan) != Tls_ChannelType()) {
	Tcl_AppendResult(interp, "bad channel \"", Tcl_GetChannelName(chan),
		"\": not a TLS channel", (char *)NULL);
	Tcl_SetErrorCode(interp, "TLS", "HANDSHAKE", "CHANNEL", "INVALID", (char *)NULL);
	return(TCL_ERROR);
    }
    statePtr = (State *)Tcl_GetChannelInstanceData(chan);

    dprintf("Calling Tls_WaitForConnect");
    ret = Tls_WaitForConnect(statePtr, &err, 1);
    dprintf("Tls_WaitForConnect returned: %i", ret);

    if (ret < 0 && ((statePtr->flags & TLS_TCL_ASYNC) && (err == EAGAIN))) {
	dprintf("Async set and err = EAGAIN");
	ret = 0;
    } else if (ret < 0) {
	long result;
	errStr = statePtr->err;
	Tcl_ResetResult(interp);
	Tcl_SetErrno(err);

	if (!errStr || (*errStr == 0)) {
	    errStr = Tcl_PosixError(interp);
	}

	Tcl_AppendResult(interp, "handshake failed: ", errStr, (char *)NULL);
	if ((result = SSL_get_verify_result(statePtr->ssl)) != X509_V_OK) {
	    Tcl_AppendResult(interp, " due to \"", X509_verify_cert_error_string(result), "\"", (char *)NULL);
	}
	Tcl_SetErrorCode(interp, "TLS", "HANDSHAKE", "FAILED", (char *)NULL);
	dprintf("Returning TCL_ERROR with handshake failed: %s", errStr);
	return(TCL_ERROR);
    } else {
	if (err != 0) {
	    dprintf("Got an error with a completed handshake: err = %i", err);
	}
	ret = 1;
    }

    dprintf("Returning TCL_OK with data \"%i\"", ret);
    Tcl_SetObjResult(interp, Tcl_NewIntObj(ret));
    return(TCL_OK);
}

/*
 *-------------------------------------------------------------------
 *
 * ImportObjCmd --
 *
 *	This procedure is invoked to process the "ssl" command
 *
 *	The ssl command pushes SSL over a (newly connected) tcp socket
 *
 * Results:
 *	A standard Tcl result.
 *
 * Side effects:
 *	May modify the behavior of an IO channel.
 *
 *-------------------------------------------------------------------
 */

static int
ImportObjCmd(
    TCL_UNUSED(void *),
    Tcl_Interp *interp,
    int objc,
    Tcl_Obj *const objv[])
{
    Tcl_Channel chan;		/* The channel to set a mode on. */
    State *statePtr;		/* client state for ssl socket */
    SSL_CTX *ctx		= NULL;
    Tcl_Obj *script		= NULL;
    Tcl_Obj *password		= NULL;
    Tcl_DString upperChannelTranslation, upperChannelBlocking, upperChannelEncoding, upperChannelEOFChar;
    int idx;
    Tcl_Size len;
    int flags			= TLS_TCL_INIT;
    int server			= 0;	/* is connection incoming or outgoing? */
    char *keyfile		= NULL;
    char *certfile		= NULL;
    unsigned char *key		= NULL;
    Tcl_Size key_len		= 0;
    unsigned char *cert		= NULL;
    Tcl_Size cert_len		= 0;
    char *ciphers		= NULL;
    char *CAfile		= NULL;
    char *CAdir			= NULL;
    char *DHparams		= NULL;
    char *model			= NULL;
#ifndef OPENSSL_NO_TLSEXT
    char *servername		= NULL;	/* hostname for Server Name Indication */
#endif
    int ssl2 = 0, ssl3 = 0;
    int tls1 = 1, tls1_1 = 1, tls1_2 = 1, tls1_3 = 1;
    int proto = 0;
    int verify = 0, require = 0, request = 1;

    dprintf("Called");

#if defined(NO_TLS1)
    tls1 = 0;
#endif
#if defined(NO_TLS1_1)
    tls1_1 = 0;
#endif
#if defined(NO_TLS1_2)
    tls1_2 = 0;
#endif
#if defined(NO_TLS1_3)
    tls1_3 = 0;
#endif

    if (objc < 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "channel ?options?");
	return TCL_ERROR;
    }

    chan = Tcl_GetChannel(interp, Tcl_GetString(objv[1]), NULL);
    if (chan == (Tcl_Channel) NULL) {
	return TCL_ERROR;
    }

    /*
     * Make sure to operate on the topmost channel
     */
    chan = Tcl_GetTopChannel(chan);

    for (idx = 2; idx < objc; idx++) {
	char *opt = Tcl_GetString(objv[idx]);

	if (opt[0] != '-')
	    break;

	OPTSTR("-cadir", CAdir);
	OPTSTR("-cafile", CAfile);
	OPTSTR("-certfile", certfile);
	OPTSTR("-cipher", ciphers);
	OPTOBJ("-command", script);
	OPTSTR("-dhparams", DHparams);
	OPTSTR("-keyfile", keyfile);
	OPTSTR("-model", model);
	OPTOBJ("-password", password);
	OPTBOOL("-require", require);
	OPTBOOL("-request", request);
	OPTBOOL("-server", server);
#ifndef OPENSSL_NO_TLSEXT
	OPTSTR( "-servername", servername);
#endif

	OPTBOOL("-ssl2", ssl2);
	OPTBOOL("-ssl3", ssl3);
	OPTBOOL("-tls1", tls1);
	OPTBOOL("-tls1.1", tls1_1);
	OPTBOOL("-tls1.2", tls1_2);
	OPTBOOL("-tls1.3", tls1_3)
	OPTBYTE("-cert", cert, cert_len);
	OPTBYTE("-key", key, key_len);

	OPTBAD("option", "-cadir, -cafile, -cert, -certfile, -cipher, -command, -dhparams, -key, -keyfile, -model, -password, -require, -request, -server, -servername, -ssl2, -ssl3, -tls1, -tls1.1, -tls1.2, or tls1.3");

	return TCL_ERROR;
    }
    if (request)	    verify |= SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_PEER;
    if (request && require) verify |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    if (verify == 0)	verify = SSL_VERIFY_NONE;

    proto |= (ssl2 ? TLS_PROTO_SSL2 : 0);
    proto |= (ssl3 ? TLS_PROTO_SSL3 : 0);
    proto |= (tls1 ? TLS_PROTO_TLS1 : 0);
    proto |= (tls1_1 ? TLS_PROTO_TLS1_1 : 0);
    proto |= (tls1_2 ? TLS_PROTO_TLS1_2 : 0);
    proto |= (tls1_3 ? TLS_PROTO_TLS1_3 : 0);

    /* reset to NULL if blank string provided */
    if (cert && !*cert)		        cert	        = NULL;
    if (key && !*key)		        key	        = NULL;
    if (certfile && !*certfile)         certfile	= NULL;
    if (keyfile && !*keyfile)		keyfile	        = NULL;
    if (ciphers && !*ciphers)	        ciphers	        = NULL;
    if (CAfile && !*CAfile)	        CAfile	        = NULL;
    if (CAdir && !*CAdir)	        CAdir	        = NULL;
    if (DHparams && !*DHparams)	        DHparams        = NULL;

    /* new SSL state */
    statePtr		= (State *) ckalloc((unsigned) sizeof(State));
    memset(statePtr, 0, sizeof(State));

    statePtr->flags	= flags;
    statePtr->interp	= interp;
    statePtr->vflags	= verify;
    statePtr->err	= "";

    /* allocate script */
    if (script) {
	(void) Tcl_GetStringFromObj(script, &len);
	if (len) {
	    statePtr->callback = script;
	    Tcl_IncrRefCount(statePtr->callback);
	}
    }

    /* allocate password */
    if (password) {
	(void) Tcl_GetStringFromObj(password, &len);
	if (len) {
	    statePtr->password = password;
	    Tcl_IncrRefCount(statePtr->password);
	}
    }

    if (model != NULL) {
	int mode;
	/* Get the "model" context */
	chan = Tcl_GetChannel(interp, model, &mode);
	if (chan == (Tcl_Channel) NULL) {
	    Tls_Free((void *)statePtr);
	    return TCL_ERROR;
	}

	/*
	 * Make sure to operate on the topmost channel
	 */
	chan = Tcl_GetTopChannel(chan);
	if (Tcl_GetChannelType(chan) != Tls_ChannelType()) {
	    Tcl_AppendResult(interp, "bad channel \"", Tcl_GetChannelName(chan),
		    "\": not a TLS channel", (char *)NULL);
	    Tcl_SetErrorCode(interp, "TLS", "IMPORT", "CHANNEL", "INVALID", (char *)NULL);
	    Tls_Free((void *)statePtr);
	    return TCL_ERROR;
	}
	ctx = ((State *)Tcl_GetChannelInstanceData(chan))->ctx;
    } else {
	if ((ctx = CTX_Init(statePtr, server, proto, keyfile, certfile, key,
		cert, key_len, cert_len, CAdir, CAfile, ciphers,
		DHparams)) == NULL) {
	    Tls_Free((void *)statePtr);
	    return TCL_ERROR;
	}
    }

    statePtr->ctx = ctx;

    /*
     * We need to make sure that the channel works in binary (for the
     * encryption not to get goofed up).
     * We only want to adjust the buffering in pre-v2 channels, where
     * each channel in the stack maintained its own buffers.
     */
    Tcl_DStringInit(&upperChannelTranslation);
    Tcl_DStringInit(&upperChannelBlocking);
    Tcl_DStringInit(&upperChannelEOFChar);
    Tcl_DStringInit(&upperChannelEncoding);
    Tcl_GetChannelOption(interp, chan, "-eofchar", &upperChannelEOFChar);
    Tcl_GetChannelOption(interp, chan, "-encoding", &upperChannelEncoding);
    Tcl_GetChannelOption(interp, chan, "-translation", &upperChannelTranslation);
    Tcl_GetChannelOption(interp, chan, "-blocking", &upperChannelBlocking);
    Tcl_SetChannelOption(interp, chan, "-translation", "binary");
    Tcl_SetChannelOption(interp, chan, "-blocking", "true");
    dprintf("Consuming Tcl channel %s", Tcl_GetChannelName(chan));
    statePtr->self = Tcl_StackChannel(interp, Tls_ChannelType(), statePtr, (TCL_READABLE | TCL_WRITABLE), chan);
    dprintf("Created channel named %s", Tcl_GetChannelName(statePtr->self));
    if (statePtr->self == (Tcl_Channel) NULL) {
	/*
	 * No use of Tcl_EventuallyFree because no possible Tcl_Preserve.
	 */
	Tls_Free((void *)statePtr);
	return TCL_ERROR;
    }

    Tcl_SetChannelOption(interp, statePtr->self, "-translation", Tcl_DStringValue(&upperChannelTranslation));
    Tcl_SetChannelOption(interp, statePtr->self, "-encoding", Tcl_DStringValue(&upperChannelEncoding));
    Tcl_SetChannelOption(interp, statePtr->self, "-eofchar", Tcl_DStringValue(&upperChannelEOFChar));
    Tcl_SetChannelOption(interp, statePtr->self, "-blocking", Tcl_DStringValue(&upperChannelBlocking));

    /*
     * SSL Initialization
     */

    statePtr->ssl = SSL_new(statePtr->ctx);
    if (!statePtr->ssl) {
	/* SSL library error */
	Tcl_AppendResult(interp, "couldn't construct ssl session: ", GET_ERR_REASON(), (char *)NULL);
	Tcl_SetErrorCode(interp, "TLS", "IMPORT", "INIT", "FAILED", (char *)NULL);
	Tls_Free((void *)statePtr);
	return TCL_ERROR;
    }

#ifndef OPENSSL_NO_TLSEXT
    if (servername) {
	if (!SSL_set_tlsext_host_name(statePtr->ssl, servername) && require) {
	    Tcl_AppendResult(interp, "setting TLS host name extension failed", (char *)NULL);
	    Tcl_SetErrorCode(interp, "TLS", "IMPORT", "HOSTNAME", "FAILED", (char *)NULL);
	    Tls_Free((void *)statePtr);
	    return TCL_ERROR;
	}
    }
#endif

    /*
     * SSL Callbacks
     */
    SSL_set_app_data(statePtr->ssl, (void *)statePtr);	/* point back to us */
    SSL_set_verify(statePtr->ssl, verify, VerifyCallback);
    SSL_CTX_set_info_callback(statePtr->ctx, InfoCallback);

    /* Create Tcl_Channel BIO Handler */
    statePtr->p_bio	= BIO_new_tcl(statePtr, BIO_NOCLOSE);
    statePtr->bio	= BIO_new(BIO_f_ssl());

    if (server) {
	statePtr->flags |= TLS_TCL_SERVER;
	SSL_set_accept_state(statePtr->ssl);
    } else {
	SSL_set_connect_state(statePtr->ssl);
    }
    SSL_set_bio(statePtr->ssl, statePtr->p_bio, statePtr->p_bio);
    BIO_set_ssl(statePtr->bio, statePtr->ssl, BIO_NOCLOSE);

    /*
     * End of SSL Init
     */
    dprintf("Returning %s", Tcl_GetChannelName(statePtr->self));
    Tcl_SetResult(interp, (char *)Tcl_GetChannelName(statePtr->self), TCL_VOLATILE);
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * UnimportObjCmd --
 *
 *	This procedure is invoked to remove the topmost channel filter.
 *
 * Results:
 *	A standard Tcl result.
 *
 * Side effects:
 *	May modify the behavior of an IO channel.
 *
 *-------------------------------------------------------------------
 */

static int
UnimportObjCmd(
    TCL_UNUSED(void *),
    Tcl_Interp *interp,
    int objc,
    Tcl_Obj *const objv[])
{
    Tcl_Channel chan;		/* The channel to set a mode on. */

    dprintf("Called");

    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "channel");
	return TCL_ERROR;
    }

    chan = Tcl_GetChannel(interp, Tcl_GetString(objv[1]), NULL);
    if (chan == (Tcl_Channel) NULL) {
	return TCL_ERROR;
    }

    /*
     * Make sure to operate on the topmost channel
     */
    chan = Tcl_GetTopChannel(chan);

    if (Tcl_GetChannelType(chan) != Tls_ChannelType()) {
	Tcl_AppendResult(interp, "bad channel \"", Tcl_GetChannelName(chan),
		"\": not a TLS channel", (char *)NULL);
	Tcl_SetErrorCode(interp, "TLS", "UNIMPORT", "CHANNEL", "INVALID", (char *)NULL);
	return TCL_ERROR;
    }

    if (Tcl_UnstackChannel(interp, chan) == TCL_ERROR) {
	return TCL_ERROR;
    }

    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * CTX_Init -- construct a SSL_CTX instance
 *
 * Results:
 *	A valid SSL_CTX instance or NULL.
 *
 * Side effects:
 *	constructs SSL context (CTX)
 *
 *-------------------------------------------------------------------
 */

static SSL_CTX *
CTX_Init(
    State *statePtr,
    TCL_UNUSED(int) /* isServer */,
    int proto,
    char *keyfile,
    char *certfile,
    unsigned char *key,
    unsigned char *cert,
    int key_len,
    int cert_len,
    char *CAdir,
    char *CAfile,
    char *ciphers,
    char *DHparams)
{
    Tcl_Interp *interp = statePtr->interp;
    SSL_CTX *ctx = NULL;
    Tcl_DString ds;
    Tcl_DString ds1;
    int off = 0;
    int load_private_key;
    const SSL_METHOD *method;

    dprintf("Called");

    if (!proto) {
	Tcl_AppendResult(interp, "no valid protocol selected", (char *)NULL);
	return NULL;
    }

    /* create SSL context */
    if (ENABLED(proto, TLS_PROTO_SSL2)) {
	Tcl_AppendResult(interp, "SSL2 protocol not supported", (char *)NULL);
	return NULL;
    }
    if (ENABLED(proto, TLS_PROTO_SSL3)) {
	Tcl_AppendResult(interp, "SSL3 protocol not supported", (char *)NULL);
	return NULL;
    }
#if defined(NO_TLS1) || defined(OPENSSL_NO_TLS1) || defined(OPENSSL_NO_TLS1_METHOD)
    if (ENABLED(proto, TLS_PROTO_TLS1)) {
	Tcl_AppendResult(interp, "TLS 1.0 protocol not supported", (char *)NULL);
	return NULL;
    }
#endif
#if defined(NO_TLS1_1) || defined(OPENSSL_NO_TLS1_1) || defined(OPENSSL_NO_TLS1_1_METHOD)
    if (ENABLED(proto, TLS_PROTO_TLS1_1)) {
	Tcl_AppendResult(interp, "TLS 1.1 protocol not supported", (char *)NULL);
	return NULL;
    }
#endif
#if defined(NO_TLS1_2) || defined(OPENSSL_NO_TLS1_2) || defined(OPENSSL_NO_TLS1_2_METHOD)
    if (ENABLED(proto, TLS_PROTO_TLS1_2)) {
	Tcl_AppendResult(interp, "TLS 1.2 protocol not supported", (char *)NULL);
	return NULL;
    }
#endif
#if defined(NO_TLS1_3) || defined(OPENSSL_NO_TLS1_3) || defined(OPENSSL_NO_TLS1_3_METHOD)
    if (ENABLED(proto, TLS_PROTO_TLS1_3)) {
	Tcl_AppendResult(interp, "TLS 1.3 protocol not supported", (char *)NULL);
	return NULL;
    }
#endif

    switch (proto) {
#if !defined(NO_TLS1) && !defined(OPENSSL_NO_TLS1) && !defined(OPENSSL_NO_TLS1_METHOD)
    case TLS_PROTO_TLS1:
	method = TLSv1_method();
	break;
#endif
#if !defined(NO_TLS1_1) && !defined(OPENSSL_NO_TLS1_1) && !defined(OPENSSL_NO_TLS1_1_METHOD)
    case TLS_PROTO_TLS1_1:
	method = TLSv1_1_method();
	break;
#endif
#if !defined(NO_TLS1_2) && !defined(OPENSSL_NO_TLS1_2) && !defined(OPENSSL_NO_TLS1_2_METHOD)
    case TLS_PROTO_TLS1_2:
	method = TLSv1_2_method();
	break;
#endif
#if !defined(NO_TLS1_3) && !defined(OPENSSL_NO_TLS1_3) && !defined(OPENSSL_NO_TLS1_3_METHOD)
    case TLS_PROTO_TLS1_3:
	/* Use the generic method and constraint range after context is created */
	method = TLS_method();
	break;
#endif
    default:
	method = TLS_method();
#if !defined(NO_TLS1) && !defined(OPENSSL_NO_TLS1) && !defined(OPENSSL_NO_TLS1_METHOD)
	off |= (ENABLED(proto, TLS_PROTO_TLS1)   ? 0 : SSL_OP_NO_TLSv1);
#endif
#if !defined(NO_TLS1_1) && !defined(OPENSSL_NO_TLS1_1) && !defined(OPENSSL_NO_TLS1_1_METHOD)
	off |= (ENABLED(proto, TLS_PROTO_TLS1_1) ? 0 : SSL_OP_NO_TLSv1_1);
#endif
#if !defined(NO_TLS1_2) && !defined(OPENSSL_NO_TLS1_2) && !defined(OPENSSL_NO_TLS1_2_METHOD)
	off |= (ENABLED(proto, TLS_PROTO_TLS1_2) ? 0 : SSL_OP_NO_TLSv1_2);
#endif
#if !defined(NO_TLS1_3) && !defined(OPENSSL_NO_TLS1_3) && !defined(OPENSSL_NO_TLS1_3_METHOD)
	off |= (ENABLED(proto, TLS_PROTO_TLS1_3) ? 0 : SSL_OP_NO_TLSv1_3);
#endif
	break;
    }

    ctx = SSL_CTX_new(method);
    if (!ctx) {
	return(NULL);
    }

#if !defined(NO_TLS1_3) && !defined(OPENSSL_NO_TLS1_3)
    if (proto == TLS_PROTO_TLS1_3) {
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    }
#endif

    SSL_CTX_set_app_data(ctx, interp);	/* remember the interpreter */
    SSL_CTX_set_options(ctx, SSL_OP_ALL);	/* all SSL bug workarounds */
    SSL_CTX_set_options(ctx, off);		/* disable protocol versions */
    SSL_CTX_sess_set_cache_size(ctx, 128);

    if (ciphers != NULL)
	SSL_CTX_set_cipher_list(ctx, ciphers);

    /* set some callbacks */
    SSL_CTX_set_default_passwd_cb(ctx, PasswordCallback);

#ifndef BSAFE
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)statePtr);
#endif

    /* read a Diffie-Hellman parameters file, or use the built-in one */
#ifdef OPENSSL_NO_DH
    if (DHparams != NULL) {
	Tcl_AppendResult(interp, "DH parameter support not available", (char *)NULL);
	SSL_CTX_free(ctx);
	return NULL;
    }
#else
    {
	DH* dh;
	if (DHparams != NULL) {
	    BIO *bio;
	    Tcl_DStringInit(&ds);
	    bio = BIO_new_file(F2N(DHparams, &ds), "r");
	    if (!bio) {
		Tcl_DStringFree(&ds);
		Tcl_AppendResult(interp, "Could not find DH parameters file", (char *)NULL);
		SSL_CTX_free(ctx);
		return NULL;
	    }

	    dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	    BIO_free(bio);
	    Tcl_DStringFree(&ds);
	    if (!dh) {
		Tcl_AppendResult(interp, "Could not read DH parameters from file", (char *)NULL);
		SSL_CTX_free(ctx);
		return NULL;
	    }
	    SSL_CTX_set_tmp_dh(ctx, dh);
	    DH_free(dh);
	} else {
	    /* Use well known DH parameters that have built-in support in OpenSSL */
	    if (!SSL_CTX_set_dh_auto(ctx, 1)) {
		Tcl_AppendResult(interp, "Could not enable set DH auto: ", GET_ERR_REASON(), (char *)NULL);
		SSL_CTX_free(ctx);
		return NULL;
	    }
	}
    }
#endif

    /* set our certificate */
    load_private_key = 0;
    if (certfile != NULL) {
	load_private_key = 1;

	Tcl_DStringInit(&ds);

	if (SSL_CTX_use_certificate_file(ctx, F2N(certfile, &ds), SSL_FILETYPE_PEM) <= 0) {
	    Tcl_DStringFree(&ds);
	    Tcl_AppendResult(interp, "unable to set certificate file ", certfile, ": ",
		    GET_ERR_REASON(), (char *)NULL);
	    SSL_CTX_free(ctx);
	    return NULL;
	}
    } else if (cert != NULL) {
	load_private_key = 1;
	if (SSL_CTX_use_certificate_ASN1(ctx, cert_len, cert) <= 0) {
	    Tcl_DStringFree(&ds);
	    Tcl_AppendResult(interp, "unable to set certificate: ",
		    GET_ERR_REASON(), (char *)NULL);
	    SSL_CTX_free(ctx);
	    return NULL;
	}
    } else {
	certfile = (char*)X509_get_default_cert_file();

	if (SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM) <= 0) {
#if 0
	    Tcl_DStringFree(&ds);
	    Tcl_AppendResult(interp, "unable to use default certificate file ", certfile, ": ",
		    GET_ERR_REASON(), (char *)NULL);
	    SSL_CTX_free(ctx);
	    return NULL;
#endif
	}
    }

    /* set our private key */
    if (load_private_key) {
	if (keyfile == NULL && key == NULL) {
	    keyfile = certfile;
	}

	if (keyfile != NULL) {
	    /* get the private key associated with this certificate */
	    if (keyfile == NULL) {
		keyfile = certfile;
	    }

	    if (SSL_CTX_use_PrivateKey_file(ctx, F2N(keyfile, &ds), SSL_FILETYPE_PEM) <= 0) {
		Tcl_DStringFree(&ds);
		/* flush the passphrase which might be left in the result */
		Tcl_SetResult(interp, NULL, TCL_STATIC);
		Tcl_AppendResult(interp, "unable to set public key file ", keyfile, " ",
			GET_ERR_REASON(), (char *)NULL);
		SSL_CTX_free(ctx);
		return NULL;
	    }
	    Tcl_DStringFree(&ds);
	} else if (key != NULL) {
	    if (SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_RSA, ctx, key,key_len) <= 0) {
		Tcl_DStringFree(&ds);
		/* flush the passphrase which might be left in the result */
		Tcl_SetResult(interp, NULL, TCL_STATIC);
		Tcl_AppendResult(interp, "unable to set public key: ", GET_ERR_REASON(), (char *)NULL);
		SSL_CTX_free(ctx);
		return NULL;
	    }
	}
	/* Now we know that a key and cert have been set against
	 * the SSL context */
	if (!SSL_CTX_check_private_key(ctx)) {
	    Tcl_AppendResult(interp,
		    "private key does not match the certificate public key",
		    (char *)NULL);
	    SSL_CTX_free(ctx);
	    return NULL;
	}
    }

    /* Set verification CAs */
    Tcl_DStringInit(&ds);
    Tcl_DStringInit(&ds1);
    if (!SSL_CTX_load_verify_locations(ctx, F2N(CAfile, &ds), F2N(CAdir, &ds1)) ||
	!SSL_CTX_set_default_verify_paths(ctx)) {
#if 0
	Tcl_DStringFree(&ds);
	Tcl_DStringFree(&ds1);
	/* Don't currently care if this fails */
	Tcl_AppendResult(interp, "SSL default verify paths: ",
		GET_ERR_REASON(), (char *)NULL);
	SSL_CTX_free(ctx);
	return NULL;
#endif
    }

    /* https://sourceforge.net/p/tls/bugs/57/ */
    /* XXX:TODO: Let the user supply values here instead of something that exists on the filesystem */
    if (CAfile != NULL) {
        STACK_OF(X509_NAME) *certNames = SSL_load_client_CA_file(F2N(CAfile, &ds));
	if (certNames != NULL) {
	    SSL_CTX_set_client_CA_list(ctx, certNames);
	}
    }

    Tcl_DStringFree(&ds);
    Tcl_DStringFree(&ds1);
    return ctx;
}

/*
 *-------------------------------------------------------------------
 *
 * StatusObjCmd -- return certificate for connected peer.
 *
 * Results:
 *	A standard Tcl result.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
static int
StatusObjCmd(
    TCL_UNUSED(void *),
    Tcl_Interp *interp,
    int objc,
    Tcl_Obj	*const objv[])
{
    State *statePtr;
    X509 *peer;
    Tcl_Obj *objPtr;
    Tcl_Channel chan;
    char *channelName, *ciphers;
    int mode;

    dprintf("Called");

    switch (objc) {
	case 2:
	    channelName = Tcl_GetString(objv[1]);
	    break;

	case 3:
	    if (!strcmp (Tcl_GetString (objv[1]), "-local")) {
		channelName = Tcl_GetString(objv[2]);
		break;
	    }
	    /* fallthrough */
	default:
	    Tcl_WrongNumArgs(interp, 1, objv, "?-local? channel");
	    return TCL_ERROR;
    }

    chan = Tcl_GetChannel(interp, channelName, &mode);
    if (chan == (Tcl_Channel) NULL) {
	return TCL_ERROR;
    }
    /*
     * Make sure to operate on the topmost channel
     */
    chan = Tcl_GetTopChannel(chan);
    if (Tcl_GetChannelType(chan) != Tls_ChannelType()) {
	Tcl_AppendResult(interp, "bad channel \"", Tcl_GetChannelName(chan),
		"\": not a TLS channel", (char *)NULL);
	Tcl_SetErrorCode(interp, "TLS", "STATUS", "CHANNEL", "INVALID", (char *)NULL);
	return TCL_ERROR;
    }
    statePtr = (State *) Tcl_GetChannelInstanceData(chan);

    /* Get certificate for peer or self */
    if (objc == 2) {
	peer = SSL_get_peer_certificate(statePtr->ssl);
    } else {
	peer = SSL_get_certificate(statePtr->ssl);
    }
    /* Get X509 certificate info */
    if (peer) {
	objPtr = Tls_NewX509Obj(interp, peer);
	if (objc == 2) {
	    X509_free(peer);
	    peer = NULL;
	}
    } else {
	objPtr = Tcl_NewListObj(0, NULL);
    }

    LAPPEND_INT(interp, objPtr, "sbits", SSL_get_cipher_bits(statePtr->ssl, NULL));

    ciphers = (char*)SSL_get_cipher(statePtr->ssl);
    if (ciphers != NULL && strcmp(ciphers, "(NONE)")!=0) {
	LAPPEND_STR(interp, objPtr, "cipher", ciphers, -1);
    }

    LAPPEND_STR(interp, objPtr, "version", SSL_get_version(statePtr->ssl), -1);

    Tcl_SetObjResult(interp, objPtr);
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * VersionObjCmd -- return version string from OpenSSL.
 *
 * Results:
 *	A standard Tcl result.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
static int
VersionObjCmd(
    TCL_UNUSED(void *),
    Tcl_Interp *interp,
    TCL_UNUSED(int) /* objc */,
    TCL_UNUSED(Tcl_Obj *const *) /* objv */)
{
    Tcl_Obj *objPtr;

    dprintf("Called");

    objPtr = Tcl_NewStringObj(OPENSSL_VERSION_TEXT, -1);

    Tcl_SetObjResult(interp, objPtr);
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * MiscObjCmd -- misc commands
 *
 * Results:
 *	A standard Tcl result.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
static int
MiscObjCmd(
    TCL_UNUSED(void *),
    Tcl_Interp *interp,
    int objc,
    Tcl_Obj	*const objv[])
{
    static const char *commands [] = { "req", NULL };
    enum command { C_REQ, C_DUMMY };
    int cmd;

    dprintf("Called");

    if (objc < 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "subcommand ?args?");
	return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], commands,
	    "command", 0, &cmd) != TCL_OK) {
	return TCL_ERROR;
    }

    ERR_clear_error();

    switch ((enum command) cmd) {
	case C_REQ: {
	    EVP_PKEY *pkey=NULL;
	    X509 *cert=NULL;
	    X509_NAME *name=NULL;
	    Tcl_Obj **listv;
	    Tcl_Size listc,i;

	    BIO *out=NULL;

	    const char *k_C="",*k_ST="",*k_L="",*k_O="",*k_OU="",*k_CN="",*k_Email="";
	    char *keyout,*pemout,*str;
	    int keysize,serial=0,days=365;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	    BIGNUM *bne = NULL;
	    RSA *rsa = NULL;
#else
	    EVP_PKEY_CTX *ctx = NULL;
#endif

	    if ((objc<5) || (objc>6)) {
		Tcl_WrongNumArgs(interp, 2, objv, "keysize keyfile certfile ?info?");
		return TCL_ERROR;
	    }

	    if (Tcl_GetIntFromObj(interp, objv[2], &keysize) != TCL_OK) {
		return TCL_ERROR;
	    }
	    keyout=Tcl_GetString(objv[3]);
	    pemout=Tcl_GetString(objv[4]);

	    if (objc>=6) {
		if (Tcl_ListObjGetElements(interp, objv[5], &listc, &listv) != TCL_OK) {
		    return TCL_ERROR;
		}

		if ((listc%2) != 0) {
		    Tcl_SetResult(interp,"Information list must have even number of arguments",NULL);
		    return TCL_ERROR;
		}
		for (i=0; i<listc; i+=2) {
		    str=Tcl_GetString(listv[i]);
		    if (strcmp(str,"days")==0) {
			if (Tcl_GetIntFromObj(interp,listv[i+1],&days)!=TCL_OK)
			    return TCL_ERROR;
		    } else if (strcmp(str,"serial")==0) {
			if (Tcl_GetIntFromObj(interp,listv[i+1],&serial)!=TCL_OK)
			    return TCL_ERROR;
		    } else if (strcmp(str,"C")==0) {
			k_C=Tcl_GetString(listv[i+1]);
		    } else if (strcmp(str,"ST")==0) {
			k_ST=Tcl_GetString(listv[i+1]);
		    } else if (strcmp(str,"L")==0) {
			k_L=Tcl_GetString(listv[i+1]);
		    } else if (strcmp(str,"O")==0) {
			k_O=Tcl_GetString(listv[i+1]);
		    } else if (strcmp(str,"OU")==0) {
			k_OU=Tcl_GetString(listv[i+1]);
		    } else if (strcmp(str,"CN")==0) {
			k_CN=Tcl_GetString(listv[i+1]);
		    } else if (strcmp(str,"Email")==0) {
			k_Email=Tcl_GetString(listv[i+1]);
		    } else {
			Tcl_SetResult(interp,"Unknown parameter",NULL);
			return TCL_ERROR;
		    }
		}
	    }
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	    bne = BN_new();
	    rsa = RSA_new();
	    pkey = EVP_PKEY_new();
	    if (bne == NULL || rsa == NULL || pkey == NULL || !BN_set_word(bne,RSA_F4) ||
		!RSA_generate_key_ex(rsa, keysize, bne, NULL) || !EVP_PKEY_assign_RSA(pkey, rsa)) {
		EVP_PKEY_free(pkey);
		/* RSA_free(rsa); freed by EVP_PKEY_free */
		BN_free(bne);
#else
	    pkey = EVP_RSA_gen((unsigned int)keysize);
	    ctx = EVP_PKEY_CTX_new(pkey,NULL);
	    if (pkey == NULL || ctx == NULL || !EVP_PKEY_keygen_init(ctx) ||
		!EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keysize) || !EVP_PKEY_keygen(ctx, &pkey)) {
		EVP_PKEY_free(pkey);
		EVP_PKEY_CTX_free(ctx);
#endif
		Tcl_SetResult(interp,"Error generating private key",NULL);
		return TCL_ERROR;
	    } else {
		out=BIO_new(BIO_s_file());
		BIO_write_filename(out,keyout);
		PEM_write_bio_PrivateKey(out,pkey,NULL,NULL,0,NULL,NULL);
		BIO_free_all(out);

		if ((cert=X509_new())==NULL) {
		    Tcl_SetResult(interp,"Error generating certificate request",NULL);
		    EVP_PKEY_free(pkey);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		    BN_free(bne);
#endif
		    return(TCL_ERROR);
		}

		X509_set_version(cert,2);
		ASN1_INTEGER_set(X509_get_serialNumber(cert),serial);
		X509_gmtime_adj(X509_getm_notBefore(cert),0);
		X509_gmtime_adj(X509_getm_notAfter(cert),(long)60*60*24*days);
		X509_set_pubkey(cert,pkey);

		name=X509_get_subject_name(cert);

		X509_NAME_add_entry_by_txt(name,"C", MBSTRING_ASC, (unsigned char *) k_C, -1, -1, 0);
		X509_NAME_add_entry_by_txt(name,"ST", MBSTRING_ASC, (unsigned char *) k_ST, -1, -1, 0);
		X509_NAME_add_entry_by_txt(name,"L", MBSTRING_ASC, (unsigned char *) k_L, -1, -1, 0);
		X509_NAME_add_entry_by_txt(name,"O", MBSTRING_ASC, (unsigned char *) k_O, -1, -1, 0);
		X509_NAME_add_entry_by_txt(name,"OU", MBSTRING_ASC, (unsigned char *) k_OU, -1, -1, 0);
		X509_NAME_add_entry_by_txt(name,"CN", MBSTRING_ASC, (unsigned char *) k_CN, -1, -1, 0);
		X509_NAME_add_entry_by_txt(name,"Email", MBSTRING_ASC, (unsigned char *) k_Email, -1, -1, 0);

		X509_set_subject_name(cert,name);

		if (!X509_sign(cert,pkey,EVP_sha256())) {
		    X509_free(cert);
		    EVP_PKEY_free(pkey);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		    BN_free(bne);
#endif
		    Tcl_SetResult(interp,"Error signing certificate",NULL);
		    return TCL_ERROR;
		}

		out=BIO_new(BIO_s_file());
		BIO_write_filename(out,pemout);
		PEM_write_bio_X509(out,cert);
		BIO_free_all(out);

		X509_free(cert);
		EVP_PKEY_free(pkey);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		BN_free(bne);
#endif
	    }
	}
	break;
    default:
	break;
    }
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * Tls_Free --
 *
 *	This procedure cleans up when a SSL socket based channel
 *	is closed and its reference count falls below 1
 *
 * Results:
 *	none
 *
 * Side effects:
 *	Frees all the state
 *
 *-------------------------------------------------------------------
 */
void
#if TCL_MAJOR_VERSION > 8
Tls_Free( void *blockPtr )
#else
Tls_Free( char *blockPtr )
#endif
{
    State *statePtr = (State *)blockPtr;

    dprintf("Called");

    Tls_Clean(statePtr);
    ckfree(blockPtr);
}

/*
 *-------------------------------------------------------------------
 *
 * Tls_Clean --
 *
 *	This procedure cleans up when a SSL socket based channel
 *	is closed and its reference count falls below 1.  This should
 *	be called synchronously by the CloseProc, not in the
 *	EventuallyFree callback.
 *
 * Results:
 *	none
 *
 * Side effects:
 *	Frees all the state
 *
 *-------------------------------------------------------------------
 */
void Tls_Clean(State *statePtr) {
    dprintf("Called");

    /*
     * we're assuming here that we're single-threaded
     */
    if (statePtr->timer != (Tcl_TimerToken) NULL) {
	Tcl_DeleteTimerHandler(statePtr->timer);
	statePtr->timer = NULL;
    }

    if (statePtr->bio) {
	/* This will call SSL_shutdown. Bug 1414045 */
	dprintf("BIO_free_all(%p)", statePtr->bio);
	BIO_free_all(statePtr->bio);
	statePtr->bio = NULL;
    }
    if (statePtr->ssl) {
	dprintf("SSL_free(%p)", statePtr->ssl);
	SSL_free(statePtr->ssl);
	statePtr->ssl = NULL;
    }
    if (statePtr->ctx) {
	SSL_CTX_free(statePtr->ctx);
	statePtr->ctx = NULL;
    }
    if (statePtr->callback) {
	Tcl_DecrRefCount(statePtr->callback);
	statePtr->callback = NULL;
    }
    if (statePtr->password) {
	Tcl_DecrRefCount(statePtr->password);
	statePtr->password = NULL;
    }

    dprintf("Returning");
}

/*
 *-------------------------------------------------------------------
 *
 * Tls_Init --
 *
 *	This is a package initialization procedure, which is called
 *	by Tcl when this package is to be added to an interpreter.
 *
 * Results:  Ssl configured and loaded
 *
 * Side effects:
 *	 create the ssl command, initialize ssl context
 *
 *-------------------------------------------------------------------
 */

#ifndef STRINGIFY
#  define STRINGIFY(x) STRINGIFY1(x)
#  define STRINGIFY1(x) #x
#endif

static const char tlsTclInitScript[] = {
#include "tls.tcl.h"
    0x00
};

DLLEXPORT int Tls_Init(
    Tcl_Interp *interp)
{
    Tcl_CmdInfo info;

    dprintf("Called");

	/*
	 * We only support Tcl 8.6 or newer
	 */
    if (Tcl_InitStubs(interp, "8.6-", 0) == NULL) {
	return TCL_ERROR;
    }

    if (TlsLibInit(0) != TCL_OK) {
	Tcl_AppendResult(interp, "could not initialize SSL library", (char *)NULL);
	return TCL_ERROR;
    }

    Tcl_CreateObjCommand(interp, "tls::ciphers", CiphersObjCmd, NULL, 0);
    Tcl_CreateObjCommand(interp, "tls::handshake", HandshakeObjCmd, NULL, 0);
    Tcl_CreateObjCommand(interp, "tls::import", ImportObjCmd, NULL, 0);
    Tcl_CreateObjCommand(interp, "tls::unimport", UnimportObjCmd, NULL, 0);
    Tcl_CreateObjCommand(interp, "tls::status", StatusObjCmd, NULL, 0);
    Tcl_CreateObjCommand(interp, "tls::version", VersionObjCmd, NULL, 0);
    Tcl_CreateObjCommand(interp, "tls::misc", MiscObjCmd, NULL, 0);

    if (interp) {
	if (Tcl_Eval(interp, tlsTclInitScript) != TCL_OK) {
	    return TCL_ERROR;
	}
    }

    if (Tcl_GetCommandInfo(interp, "::tcl::build-info", &info)) {
	Tcl_CreateObjCommand(interp, "::tls::build-info",
		info.objProc, (void *)(
		    PACKAGE_VERSION "+" STRINGIFY(TLS_VERSION_UUID)
#if defined(__clang__) && defined(__clang_major__)
			    ".clang-" STRINGIFY(__clang_major__)
#if __clang_minor__ < 10
			    "0"
#endif
			    STRINGIFY(__clang_minor__)
#endif
#if defined(__cplusplus) && !defined(__OBJC__)
			    ".cplusplus"
#endif
#ifndef NDEBUG
			    ".debug"
#endif
#if !defined(__clang__) && !defined(__INTEL_COMPILER) && defined(__GNUC__)
			    ".gcc-" STRINGIFY(__GNUC__)
#if __GNUC_MINOR__ < 10
			    "0"
#endif
			    STRINGIFY(__GNUC_MINOR__)
#endif
#ifdef __INTEL_COMPILER
			    ".icc-" STRINGIFY(__INTEL_COMPILER)
#endif
#ifdef TCL_MEM_DEBUG
			    ".memdebug"
#endif
#if defined(_MSC_VER)
			    ".msvc-" STRINGIFY(_MSC_VER)
#endif
#ifdef USE_NMAKE
			    ".nmake"
#endif
#ifndef TCL_CFG_OPTIMIZED
			    ".no-optimize"
#endif
#ifdef __OBJC__
			    ".objective-c"
#if defined(__cplusplus)
			    "plusplus"
#endif
#endif
#ifdef TCL_CFG_PROFILED
			    ".profile"
#endif
#ifdef PURIFY
			    ".purify"
#endif
#ifdef STATIC_BUILD
			    ".static"
#endif
		), NULL);
    }

    return Tcl_PkgProvideEx(interp, PACKAGE_NAME, PACKAGE_VERSION, NULL);
}

/*
 *------------------------------------------------------*
 *
 *	Tls_SafeInit --
 *
 *	------------------------------------------------*
 *	Standard procedure required by 'load'.
 *	Initializes this extension for a safe interpreter.
 *	------------------------------------------------*
 *
 *	Side effects:
 *		As of 'Tls_Init'
 *
 *	Result:
 *		A standard Tcl error code.
 *
 *------------------------------------------------------*
 */

DLLEXPORT int Tls_SafeInit(Tcl_Interp *interp) {
    dprintf("Called");
    return(Tls_Init(interp));
}

/*
 *------------------------------------------------------*
 *
 *	TlsLibInit --
 *
 *	------------------------------------------------*
 *	Initializes SSL library once per application
 *	------------------------------------------------*
 *
 *	Side effects:
 *		initializes SSL library
 *
 *	Result:
 *		none
 *
 *------------------------------------------------------*
 */
static int TlsLibInit(int uninitialize) {
    static int initialized = 0;
    int status = TCL_OK;
#if defined(OPENSSL_THREADS) && defined(TCL_THREADS)
    size_t num_locks;
#endif

    if (uninitialize) {
	if (!initialized) {
	    dprintf("Asked to uninitialize, but we are not initialized");

	    return(TCL_OK);
	}

	dprintf("Asked to uninitialize");

#if defined(OPENSSL_THREADS) && defined(TCL_THREADS)
	Tcl_MutexLock(&init_mx);

	if (locks) {
	    free(locks);
	    locks = NULL;
	    locksCount = 0;
	}
#endif
	initialized = 0;

#if defined(OPENSSL_THREADS) && defined(TCL_THREADS)
	Tcl_MutexUnlock(&init_mx);
#endif

	return(TCL_OK);
    }

    if (initialized) {
	dprintf("Called, but using cached value");
	return(status);
    }

    dprintf("Called");

#if defined(OPENSSL_THREADS) && defined(TCL_THREADS)
    Tcl_MutexLock(&init_mx);
#endif
    initialized = 1;

#if defined(OPENSSL_THREADS) && defined(TCL_THREADS)
    num_locks = CRYPTO_num_locks();
    locksCount = num_locks;
    locks = malloc(sizeof(*locks) * num_locks);
    memset(locks, 0, sizeof(*locks) * num_locks);

    CRYPTO_set_locking_callback(CryptoThreadLockCallback);
    CRYPTO_set_id_callback(CryptoThreadIdCallback);
#endif

    if (SSL_library_init() != 1) {
	status = TCL_ERROR;
	goto done;
    }

    SSL_load_error_strings();
    ERR_load_crypto_strings();

    BIO_new_tcl(NULL, 0);

done:
#if defined(OPENSSL_THREADS) && defined(TCL_THREADS)
    Tcl_MutexUnlock(&init_mx);
#endif

    return(status);
}
