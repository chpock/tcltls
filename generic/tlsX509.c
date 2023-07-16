/*
 * Copyright (C) 1997-2000 Sensus Consulting Ltd.
 * Matt Newman <matt@sensus.org>
 * Copyright (C) 2023 Brian O'Hagan
 */
#include <tcl.h>
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include "tlsInt.h"

/*
 *  Ensure these are not macros - known to be defined on Win32
 */
#ifdef min
#undef min
#endif

#ifdef max
#undef max
#endif

static int min(int a, int b)
{
    return (a < b) ? a : b;
}

static int max(int a, int b)
{
    return (a > b) ? a : b;
}

/*
 * ASN1_UTCTIME_tostr --
 */
static char *
ASN1_UTCTIME_tostr(ASN1_UTCTIME *tm)
{
    static char bp[128];
    char *v;
    int gmt=0;
    static char *mon[12]={
        "Jan","Feb","Mar","Apr","May","Jun", "Jul","Aug","Sep","Oct","Nov","Dec"};
    int i;
    int y=0,M=0,d=0,h=0,m=0,s=0;

    i=tm->length;
    v=(char *)tm->data;

    if (i < 10) goto err;
    if (v[i-1] == 'Z') gmt=1;
    for (i=0; i<10; i++)
        if ((v[i] > '9') || (v[i] < '0')) goto err;
    y= (v[0]-'0')*10+(v[1]-'0');
    if (y < 70) y+=100;
    M= (v[2]-'0')*10+(v[3]-'0');
    if ((M > 12) || (M < 1)) goto err;
    d= (v[4]-'0')*10+(v[5]-'0');
    h= (v[6]-'0')*10+(v[7]-'0');
    m=  (v[8]-'0')*10+(v[9]-'0');
    if ((v[10] >= '0') && (v[10] <= '9') && (v[11] >= '0') && (v[11] <= '9'))
        s=  (v[10]-'0')*10+(v[11]-'0');

    sprintf(bp,"%s %2d %02d:%02d:%02d %d%s", mon[M-1],d,h,m,s,y+1900,(gmt)?" GMT":"");
    return bp;
 err:
    return "Bad time value";
}

/*
 * Binary string to hex string
 */
int String_to_Hex(char* input, int len, char *output, int max) {
    int count = 0;

    for (int i = 0; i < len && count < max - 1; i++, count += 2) {
	sprintf(output + count, "%02X", input[i] & 0xff);
    }
    output[count] = 0;
    return count;
}

/*
 *------------------------------------------------------*
 *
 *	Tls_NewX509Obj --
 *
 *	------------------------------------------------*
 *	Converts a X509 certificate into a Tcl_Obj
 *	------------------------------------------------*
 *
 *	Sideeffects:
 *		None
 *
 *	Result:
 *		A Tcl List Object representing the provided
 *		X509 certificate.
 *
 *------------------------------------------------------*
 */

#define CERT_STR_SIZE 16384

Tcl_Obj*
Tls_NewX509Obj(Tcl_Interp *interp, X509 *cert) {
    Tcl_Obj *certPtr = Tcl_NewListObj(0, NULL);
    BIO *bio;
    int n;
    unsigned long flags;
    char subject[BUFSIZ];
    char issuer[BUFSIZ];
    char serial[BUFSIZ];
    char notBefore[BUFSIZ];
    char notAfter[BUFSIZ];
    char buffer[BUFSIZ];
    char certStr[CERT_STR_SIZE], *certStr_p;
    int certStr_len, toRead;
    char sha1_hash_ascii[SHA_DIGEST_LENGTH * 2 + 1];
    unsigned char sha1_hash_binary[SHA_DIGEST_LENGTH];
    char sha256_hash_ascii[SHA256_DIGEST_LENGTH * 2 + 1];
    unsigned char sha256_hash_binary[SHA256_DIGEST_LENGTH];
    int nid, pknid, bits, num_of_exts, len;
    uint32_t xflags;
    unsigned char *bstring;
    STACK_OF(GENERAL_NAME) *san;

    sha1_hash_ascii[SHA_DIGEST_LENGTH * 2] = '\0';
    sha256_hash_ascii[SHA256_DIGEST_LENGTH * 2] = '\0';

    certStr[0] = 0;
    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
	subject[0] = 0;
	issuer[0]  = 0;
	serial[0]  = 0;
    } else {
	flags = XN_FLAG_RFC2253 | ASN1_STRFLGS_UTF8_CONVERT;
	flags &= ~ASN1_STRFLGS_ESC_MSB;

	X509_NAME_print_ex(bio, X509_get_subject_name(cert), 0, flags);
	n = BIO_read(bio, subject, min(BIO_pending(bio), BUFSIZ - 1));
	n = max(n, 0);
	subject[n] = 0;
	(void)BIO_flush(bio);

	X509_NAME_print_ex(bio, X509_get_issuer_name(cert), 0, flags);
	n = BIO_read(bio, issuer, min(BIO_pending(bio), BUFSIZ - 1));
	n = max(n, 0);
	issuer[n] = 0;
	(void)BIO_flush(bio);

	i2a_ASN1_INTEGER(bio, X509_get0_serialNumber(cert));
	n = BIO_read(bio, serial, min(BIO_pending(bio), BUFSIZ - 1));
	n = max(n, 0);
	serial[n] = 0;
	(void)BIO_flush(bio);

        /* Get certificate */
        if (PEM_write_bio_X509(bio, cert)) {
            certStr_p = certStr;
            certStr_len = 0;
            while (1) {
                toRead = min(BIO_pending(bio), CERT_STR_SIZE - certStr_len - 1);
                toRead = min(toRead, BUFSIZ);
                if (toRead == 0) {
                    break;
                }
                dprintf("Reading %i bytes from the certificate...", toRead);
                n = BIO_read(bio, certStr_p, toRead);
                if (n <= 0) {
                    break;
                }
                certStr_len += n;
                certStr_p   += n;
            }
            *certStr_p = '\0';
            (void)BIO_flush(bio);
        }

	/* All */
	if (X509_print_ex(bio, cert, flags, 0)) {
	    char all[65536];
	    n = BIO_read(bio, all, min(BIO_pending(bio), 65535));
	    n = max(n, 0);
	    all[n] = 0;
	    (void)BIO_flush(bio);
	    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("all", -1));
	    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(all, n));
	}

	BIO_free(bio);
    }

    strcpy(notBefore, ASN1_UTCTIME_tostr(X509_get0_notBefore(cert)));
    strcpy(notAfter, ASN1_UTCTIME_tostr(X509_get0_notAfter(cert)));

    /* Version */
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("version", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewLongObj(X509_get_version(cert)+1));

    /* Signature algorithm */
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("signature", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(OBJ_nid2ln(X509_get_signature_nid(cert)),-1));
 
    /* Information about the signature of certificate cert */
    if (X509_get_signature_info(cert, &nid, &pknid, &bits, &xflags) == 1) {
	ASN1_BIT_STRING *key;

	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("signingDigest", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(OBJ_nid2ln(nid),-1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("publicKeyAlgorithm", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(OBJ_nid2ln(pknid),-1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("bits", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewIntObj(bits));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("extension_flags", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewIntObj(xflags));
	
	/* Public key - X509_get0_pubkey */
	key = X509_get0_pubkey_bitstr(cert);
	len = String_to_Hex(key->data, key->length, buffer, BUFSIZ);
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("publicKey", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(buffer, len));
	
	/* Check if cert was issued by CA cert issuer or self signed */
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("self_signed", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewBooleanObj(X509_check_issued(cert, cert) == X509_V_OK));
    }

    /* Unique Ids */
    {
	const ASN1_BIT_STRING *iuid, *suid;
        X509_get0_uids(cert, &iuid, &suid);
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("issuerUniqueId", -1));
	if (iuid != NULL) {
	    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewByteArrayObj((char *)iuid->data, iuid->length));
	} else {
	    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("", -1));
	}

	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("subjectUniqueId", -1));
	if (suid != NULL) {
	    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewByteArrayObj((char *)suid->data, suid->length));
	} else {
	    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("", -1));
	}
    }

    /* SHA1 Fingerprint of cert - DER representation */
    X509_digest(cert, EVP_sha1(), sha1_hash_binary, &len);
    len = String_to_Hex(sha1_hash_binary, len, sha1_hash_ascii, BUFSIZ);
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("sha1_hash", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(sha1_hash_ascii, len));

    /* SHA256 Fingerprint of cert - DER representation */
    X509_digest(cert, EVP_sha256(), sha256_hash_binary, &len);
    len = String_to_Hex(sha256_hash_binary, len, sha256_hash_ascii, BUFSIZ);
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("sha256_hash", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj( sha256_hash_ascii, SHA256_DIGEST_LENGTH * 2));

    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("subject", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj( subject, -1));

    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("issuer", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj( issuer, -1));

    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("notBefore", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj( notBefore, -1));

    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("notAfter", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj( notAfter, -1));

    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("serialNumber", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj( serial, -1));

    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("certificate", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj( certStr, -1));

    num_of_exts = X509_get_ext_count(cert);
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("num_extensions", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewIntObj(num_of_exts));

    /* Get extensions */
    if (num_of_exts > 0) {
	Tcl_Obj *extsPtr = Tcl_NewListObj(0, NULL);
	const STACK_OF(X509_EXTENSION) *exts;
	exts = X509_get0_extensions(cert);

	for (int i=0; i < num_of_exts; i++) {
	    X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
	    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
	    unsigned nid2 = OBJ_obj2nid(obj);
	    Tcl_ListObjAppendElement(interp, extsPtr, Tcl_NewStringObj(OBJ_nid2ln(nid2), -1));
	}
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("extensions", -1));
	Tcl_ListObjAppendElement(interp, certPtr, extsPtr);
    }

    /* Subject Alternative Name (SAN) extension. Additional host names for a single SSL certificate. */
    san = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (san) {
	Tcl_Obj *namesPtr = Tcl_NewListObj(0, NULL);

	for (int i=0; i < sk_GENERAL_NAME_num(san); i++)         {
	    const GENERAL_NAME *name = sk_GENERAL_NAME_value(san, i);
	    size_t len2;

	    if (name) {
		if (name->type == GEN_DNS) {
		    char *dns_name;
		    if ((len2 = ASN1_STRING_to_UTF8(&dns_name, name->d.dNSName)) > 0) {
			Tcl_ListObjAppendElement(interp, namesPtr, Tcl_NewStringObj(dns_name, (int)len2));
			OPENSSL_free (dns_name);
		    }
		} else if (name->type == GEN_IPADD) {
		    /* name->d.iPAddress */
		}
	    }
	}
	sk_GENERAL_NAME_pop_free(san, GENERAL_NAME_free);
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("subjectAltName", -1));
	Tcl_ListObjAppendElement(interp, certPtr, namesPtr);
    }

    /* Certificate Alias  */
    len = 0;
    bstring = X509_alias_get0(cert, &len);
    len = String_to_Hex(bstring, len, buffer, BUFSIZ);
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("alias", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(buffer, len));

    /* Get Subject Key id, Authority Key id */
    {
	ASN1_OCTET_STRING *astring;
	/* X509_keyid_get0 */
	astring = X509_get0_subject_key_id(cert);
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("subjectKeyIdentifier", -1));
	if (astring != NULL) {
	    len = String_to_Hex((char *)ASN1_STRING_get0_data(astring), ASN1_STRING_length(astring), buffer, BUFSIZ);
	    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewByteArrayObj(buffer, len));
	} else {
	    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("", -1));
	}

	astring = X509_get0_authority_key_id(cert);
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("authorityKeyIdentifier", -1));
	if (astring != NULL) {
	    len = String_to_Hex((char *)ASN1_STRING_get0_data(astring), ASN1_STRING_length(astring), buffer, BUFSIZ);
	    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewByteArrayObj(buffer, len));
	} else {
	    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("", -1));
	}
	
	/*  const GENERAL_NAMES *X509_get0_authority_issuer(cert);
	const ASN1_INTEGER *X509_get0_authority_serial(cert); */
    }

    /* Get OSCP URL */
    {
	STACK_OF(OPENSSL_STRING) *str_stack = X509_get1_ocsp(cert);
	Tcl_Obj *urlsPtr = Tcl_NewListObj(0, NULL);

	for (int i = 0; i < sk_OPENSSL_STRING_num(str_stack); i++) {
	    Tcl_ListObjAppendElement(interp, urlsPtr,
		Tcl_NewStringObj(sk_OPENSSL_STRING_value(str_stack, i), -1));
	}

	X509_email_free(str_stack);
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("ocsp", -1));
	Tcl_ListObjAppendElement(interp, certPtr, urlsPtr);
    }
 
    /* Signature algorithm and value */
    {
	const X509_ALGOR *sig_alg;
	const ASN1_BIT_STRING *sig;
	int sig_nid;

	X509_get0_signature(&sig, &sig_alg, cert);
	/* sig_nid = X509_get_signature_nid(cert) */
	sig_nid = OBJ_obj2nid(sig_alg->algorithm);

	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("signatureAlgorithm", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(OBJ_nid2ln(sig_nid),-1));

	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("signatureValue", -1));
	if (sig_nid != NID_undef) {
	    len = String_to_Hex(sig->data, sig->length, buffer, BUFSIZ);
	    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(buffer, len));
	} else {
	    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("", -1));
	}
    }

    return certPtr;
}
