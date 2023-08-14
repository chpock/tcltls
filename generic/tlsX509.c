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

/* Define maximum certificate size. Max PEM size 100kB and DER size is 24kB. */
#define CERT_STR_SIZE 32768

/* Common macros */
#define LAPPEND_STR(interp, obj, text, value, size) {\
    if (text != NULL) Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(text, -1)); \
    Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(value, size)); \
}
#define LAPPEND_INT(interp, obj, text, value) {\
    if (text != NULL) Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(text, -1)); \
    Tcl_ListObjAppendElement(interp, obj, Tcl_NewIntObj(value)); \
}
#define LAPPEND_LONG(interp, obj, text, value) {\
    if (text != NULL) Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(text, -1)); \
    Tcl_ListObjAppendElement(interp, obj, Tcl_NewLongObj(value)); \
}
#define LAPPEND_BOOL(interp, obj, text, value) {\
    if (text != NULL) Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(text, -1)); \
    Tcl_ListObjAppendElement(interp, obj, Tcl_NewBooleanObj(value)); \
}
#define LAPPEND_LIST(interp, obj, text, listObj) {\
    if (text != NULL) Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(text, -1)); \
    Tcl_ListObjAppendElement(interp, obj, listObj); \
}

/*
 * Binary string to hex string
 */
int String_to_Hex(char* input, int len, char *output, int size) {
    int count = 0;

    for (int i = 0; i < len && count < size - 1; i++, count += 2) {
	sprintf(output + count, "%02X", input[i] & 0xff);
    }
    output[count] = 0;
    return count;
}

/*
 * BIO to Buffer
 */
int BIO_to_Buffer(int result, BIO *bio, void *buffer, int size) {
    int len = 0;
    int pending = BIO_pending(bio);

    if (result) {
	len = BIO_read(bio, buffer, (pending < size) ? pending : size);
	(void)BIO_flush(bio);
	if (len < 0) {
	    len = 0;
	}
    }
    return len;
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
 *	Side effects:
 *		None
 *
 *	Result:
 *		A Tcl List Object representing the provided
 *		X509 certificate.
 *
 *------------------------------------------------------*
 */

Tcl_Obj*
Tls_NewX509Obj(Tcl_Interp *interp, X509 *cert) {
    Tcl_Obj *certPtr = Tcl_NewListObj(0, NULL), *listPtr;
    BIO *bio = BIO_new(BIO_s_mem());
    int mdnid, pknid, bits, len;
    uint32_t xflags, usage;
    char buffer[BUFSIZ];
    unsigned char md[EVP_MAX_MD_SIZE];
    STACK_OF(GENERAL_NAME) *names;
    STACK_OF(DIST_POINT) *crl;
    STACK_OF(OPENSSL_STRING) *ocsp;
    unsigned long flags = XN_FLAG_RFC2253 | ASN1_STRFLGS_UTF8_CONVERT;
    flags &= ~ASN1_STRFLGS_ESC_MSB;

    if (bio == NULL || certPtr == NULL) {
	return NULL;
    }

    /* Signature algorithm and value - RFC 5280 section 4.1.1.2 and 4.1.1.3 */
    /* signatureAlgorithm is the id of the cryptographic algorithm used by the
	CA to sign this cert. signatureValue is the digital signature computed
	upon the ASN.1 DER encoded tbsCertificate. */
    {
	const X509_ALGOR *sig_alg;
	const ASN1_BIT_STRING *sig;
	int sig_nid;

	X509_get0_signature(&sig, &sig_alg, cert);
	/* sig_nid = X509_get_signature_nid(cert) */
	sig_nid = OBJ_obj2nid(sig_alg->algorithm);
	LAPPEND_STR(interp, certPtr, "signatureAlgorithm", OBJ_nid2ln(sig_nid), -1);
	len = (sig_nid != NID_undef) ? String_to_Hex(sig->data, sig->length, buffer, BUFSIZ) : 0;
	LAPPEND_STR(interp, certPtr, "signatureValue", buffer, len);
    }

    /* Version of the encoded certificate - RFC 5280 section 4.1.2.1 */
    LAPPEND_LONG(interp, certPtr, "version", X509_get_version(cert)+1);

    /* Unique number assigned by CA to certificate - RFC 5280 section 4.1.2.2 */
    len = BIO_to_Buffer(i2a_ASN1_INTEGER(bio, X509_get0_serialNumber(cert)), bio, buffer, BUFSIZ);
    LAPPEND_STR(interp, certPtr, "serialNumber", buffer, len);

    /* Signature algorithm used by the CA to sign the certificate. Must match
	signatureAlgorithm. RFC 5280 section 4.1.2.3 */
    LAPPEND_STR(interp, certPtr, "signature", OBJ_nid2ln(X509_get_signature_nid(cert)), -1);

    /* Issuer identifies the entity that signed and issued the cert. RFC 5280 section 4.1.2.4 */
    len = BIO_to_Buffer(X509_NAME_print_ex(bio, X509_get_issuer_name(cert), 0, flags), bio, buffer, BUFSIZ);
    LAPPEND_STR(interp, certPtr, "issuer", buffer, len);

    /* Certificate validity period is the interval the CA warrants that it will
	maintain info on the status of the certificate. RFC 5280 section 4.1.2.5 */
    /* Get Validity - Not Before */
    len = BIO_to_Buffer(ASN1_TIME_print(bio, X509_get0_notBefore(cert)), bio, buffer, BUFSIZ);
    LAPPEND_STR(interp, certPtr, "notBefore", buffer, len);

    /* Get Validity - Not After */
    len = BIO_to_Buffer(ASN1_TIME_print(bio, X509_get0_notAfter(cert)), bio, buffer, BUFSIZ);
    LAPPEND_STR(interp, certPtr, "notAfter", buffer, len);

    /* Subject identifies the entity associated with the public key stored in
	the subject public key field. RFC 5280 section 4.1.2.6 */
    len = BIO_to_Buffer(X509_NAME_print_ex(bio, X509_get_subject_name(cert), 0, flags), bio, buffer, BUFSIZ);
    LAPPEND_STR(interp, certPtr, "subject", buffer, len);

    /* SHA1 Fingerprint of cert - DER representation */
    if (X509_digest(cert, EVP_sha1(), md, &len)) {
    len = String_to_Hex(md, len, buffer, BUFSIZ);
	LAPPEND_STR(interp, certPtr, "sha1_hash", buffer, len);
    }

    /* SHA256 Fingerprint of cert - DER representation */
    if (X509_digest(cert, EVP_sha256(), md, &len)) {
    len = String_to_Hex(md, len, buffer, BUFSIZ);
	LAPPEND_STR(interp, certPtr, "sha256_hash", buffer, len);
    }

    /* Subject Public Key Info specifies the public key and identifies the
	algorithm with which the key is used. RFC 5280 section 4.1.2.7 */
    if (X509_get_signature_info(cert, &mdnid, &pknid, &bits, &xflags)) {
	ASN1_BIT_STRING *key;
	unsigned int n;

	LAPPEND_STR(interp, certPtr, "signingDigest", OBJ_nid2ln(mdnid), -1);
	LAPPEND_STR(interp, certPtr, "publicKeyAlgorithm", OBJ_nid2ln(pknid), -1);
	LAPPEND_INT(interp, certPtr, "bits", bits); /* Effective security bits */

	key = X509_get0_pubkey_bitstr(cert);
	len = String_to_Hex(key->data, key->length, buffer, BUFSIZ);
	LAPPEND_STR(interp, certPtr, "publicKey", buffer, len);

	len = 0;
	if (X509_pubkey_digest(cert, EVP_get_digestbynid(pknid), md, &n)) {
	    len = String_to_Hex(md, (int)n, buffer, BUFSIZ);
	}
	LAPPEND_STR(interp, certPtr, "publicKeyHash", buffer, len);

	len = 0;
	if (X509_digest(cert, EVP_get_digestbynid(mdnid), md, &n)) {
	    len = String_to_Hex(md, (int)n, buffer, BUFSIZ);
	}
	LAPPEND_STR(interp, certPtr, "signatureHash", buffer, len);
    }

    /* Get extensions flags */
    xflags = X509_get_extension_flags(cert);
    LAPPEND_INT(interp, certPtr, "extFlags", xflags);

	/* Check if cert was issued by CA cert issuer or self signed */
    LAPPEND_BOOL(interp, certPtr, "selfIssued", xflags & EXFLAG_SI);
    LAPPEND_BOOL(interp, certPtr, "selfSigned", xflags & EXFLAG_SS);

    /* The Unique Ids are used to handle the possibility of reuse of subject
	and/or issuer names over time. RFC 5280 section 4.1.2.8 */
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

    /* X509 v3 Extensions - RFC 5280 section 4.1.2.9 */
    len = X509_get_ext_count(cert);
    listPtr = Tcl_NewListObj(0, NULL);
    if (len > 0) {
	const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(cert);

	for (int i=0; i < len; i++) {
	    X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
	    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);

	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj(OBJ_nid2ln(OBJ_obj2nid(obj)), -1));
	}
    }
    LAPPEND_INT(interp, certPtr, "extCount", len);
    LAPPEND_LIST(interp, certPtr, "extensions", listPtr);

    /* Authority Key Identifier (AKI) is the Subject Key Identifier (SKI) of
	its signer (the CA). RFC 5280 section 4.2.1.1, NID_authority_key_identifier */
    {
	ASN1_OCTET_STRING *astring = X509_get0_authority_key_id(cert);
	len = 0;
	if (astring != NULL) {
	    len = String_to_Hex((char *)ASN1_STRING_get0_data(astring),
		ASN1_STRING_length(astring), buffer, BUFSIZ);
	}
	LAPPEND_STR(interp, certPtr, "authorityKeyIdentifier", buffer, len);
    }

    /* Subject Key Identifier (SKI) is used to dentify certificates that contain
	a particular public key. RFC 5280 section 4.2.1.2, NID_subject_key_identifier */
    {
	ASN1_OCTET_STRING *astring = X509_get0_subject_key_id(cert);
	len = 0;
	if (astring != NULL) {
	    len = String_to_Hex((char *)ASN1_STRING_get0_data(astring),
		ASN1_STRING_length(astring), buffer, BUFSIZ);
	}
	LAPPEND_STR(interp, certPtr, "subjectKeyIdentifier", buffer, len);
    }

    /* Key usage extension defines the purpose (e.g., encipherment, signature, certificate
	signing) of the key contained in the certificate. RFC 5280 section 4.2.1.3, NID_key_usage */
    listPtr = Tcl_NewListObj(0, NULL);
    usage = X509_get_key_usage(cert);
    if ((xflags & EXFLAG_KUSAGE) && usage < 0xffffff) {
	if (usage & KU_DIGITAL_SIGNATURE) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Digital Signature", -1));
	}
	if (usage & KU_NON_REPUDIATION) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Non-Repudiation", -1));
	}
	if (usage & KU_KEY_ENCIPHERMENT) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Key Encipherment", -1));
	}
	if (usage & KU_DATA_ENCIPHERMENT) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Data Encipherment", -1));
	}
	if (usage & KU_KEY_AGREEMENT) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Key Agreement", -1));
	}
	if (usage & KU_KEY_CERT_SIGN) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Certificate Signing", -1));
	}
	if (usage & KU_CRL_SIGN) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("CRL Signing", -1));
	}
	if (usage & KU_ENCIPHER_ONLY) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Encipher Only", -1));
	}
	if (usage & KU_DECIPHER_ONLY) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Decipher Only", -1));
	}
    }
    LAPPEND_LIST(interp, certPtr, "keyUsage", listPtr);

    /* Certificate Purpose */
    {
	char *purpose = NULL;

	if (X509_check_purpose(cert, X509_PURPOSE_SSL_CLIENT, 0) > 0) {
	    purpose = "SSL Client";
	} else if (X509_check_purpose(cert, X509_PURPOSE_SSL_SERVER, 0) > 0) {
	    purpose = "SSL Server";
	} else if (X509_check_purpose(cert, X509_PURPOSE_NS_SSL_SERVER, 0) > 0) {
	    purpose = "MSS SSL Server";
	} else if (X509_check_purpose(cert, X509_PURPOSE_SMIME_SIGN, 0) > 0) {
	    purpose = "SMIME Signing";
	} else if (X509_check_purpose(cert, X509_PURPOSE_SMIME_ENCRYPT, 0) > 0) {
	    purpose = "SMIME Encryption";
	} else if (X509_check_purpose(cert, X509_PURPOSE_CRL_SIGN, 0) > 0) {
	    purpose = "CRL Signing";
	} else if (X509_check_purpose(cert, X509_PURPOSE_ANY, 0) > 0) {
	    purpose = "Any";
	} else if (X509_check_purpose(cert, X509_PURPOSE_OCSP_HELPER, 0) > 0) {
	    purpose = "OCSP Helper";
	} else if (X509_check_purpose(cert, X509_PURPOSE_TIMESTAMP_SIGN, 0) > 0) {
	    purpose = "Timestamp Signing";
	} else {
	    purpose = "";
	}
	LAPPEND_STR(interp, certPtr, "purpose", purpose, -1);
    }

    /* Get purposes */
    listPtr = Tcl_NewListObj(0, NULL);
	for (int j = 0; j < X509_PURPOSE_get_count(); j++) {
	    X509_PURPOSE *ptmp = X509_PURPOSE_get0(j);
	    Tcl_Obj *tmpPtr = Tcl_NewListObj(0, NULL);

	    for (int i = 0; i < 2; i++) {
		int idret = X509_check_purpose(cert, X509_PURPOSE_get_id(ptmp), i);
		Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj(i ? "CA" : "nonCA", -1));
		Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj(idret == 1 ? "Yes" : "No", -1));
	    }
	LAPPEND_LIST(interp, listPtr, X509_PURPOSE_get0_name(ptmp), tmpPtr);
    }
    LAPPEND_LIST(interp, certPtr, "certificatePurpose", listPtr);

    /* Certificate Policies - indicates the issuing CA considers its issuerDomainPolicy
	equivalent to the subject CA's subjectDomainPolicy. RFC 5280 section 4.2.1.4, NID_certificate_policies */
    if (xflags & EXFLAG_INVALID_POLICY) {
	/* Reject cert */
    }

    /* Policy Mappings - RFC 5280 section 4.2.1.5, NID_policy_mappings */

    /* Subject Alternative Name (SAN) contains additional URLs, DNS names, or IP
	addresses bound to certificate. RFC 5280 section 4.2.1.6, NID_subject_alt_name */
    listPtr = Tcl_NewListObj(0, NULL);
    if (names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL)) {
	for (int i=0; i < sk_GENERAL_NAME_num(names); i++) {
	    const GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);

	    len = BIO_to_Buffer(name && GENERAL_NAME_print(bio, name), bio, buffer, BUFSIZ);
	    LAPPEND_STR(interp, listPtr, NULL, buffer, len);
	}
	sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
    }
    LAPPEND_LIST(interp, certPtr, "subjectAltName", listPtr);

    /* Issuer Alternative Name is used to associate Internet style identities
	with the certificate issuer. RFC 5280 section 4.2.1.7, NID_issuer_alt_name */
    listPtr = Tcl_NewListObj(0, NULL);
    if (names = X509_get_ext_d2i(cert, NID_issuer_alt_name, NULL, NULL)) {
	for (int i=0; i < sk_GENERAL_NAME_num(names); i++) {
	    const GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);

	    len = BIO_to_Buffer(name && GENERAL_NAME_print(bio, name), bio, buffer, BUFSIZ);
	    LAPPEND_STR(interp, listPtr, NULL, buffer, len);
	}
	sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
    }
    LAPPEND_LIST(interp, certPtr, "issuerAltName", listPtr);

    /* Subject Directory Attributes provides identification attributes (e.g., nationality)
	of the subject. RFC 5280 section 4.2.1.8 (subjectDirectoryAttributes) */

    /* Basic Constraints identifies whether the subject of the cert is a CA and
	the max depth of valid cert paths for this cert. RFC 5280 section 4.2.1.9, NID_basic_constraints */
    if (xflags & EXFLAG_BCONS) {
	LAPPEND_LONG(interp, certPtr, "pathLen", X509_get_pathlen(cert));
    }
    LAPPEND_BOOL(interp, certPtr, "basicConstraintsCA", xflags & EXFLAG_CA);
    LAPPEND_BOOL(interp, certPtr, "basicConstraintsCritical", xflags & EXFLAG_CRITICAL);

    /* Name Constraints is only used in CA certs to indicate the name space for
	all subject names in subsequent certificates in a certification path
	MUST be located. RFC 5280 section 4.2.1.10, NID_name_constraints */

    /* Policy Constraints is only used in CA certs to limit the length of a
	cert chain for that CA. RFC 5280 section 4.2.1.11, NID_policy_constraints */

    /* Extended Key Usage indicates the purposes the certified public key may be
	used, beyond the basic purposes. RFC 5280 section 4.2.1.12, NID_ext_key_usage */
    listPtr = Tcl_NewListObj(0, NULL);
    if (xflags & EXFLAG_XKUSAGE) {
	usage = X509_get_extended_key_usage(cert);

	if (usage & XKU_SSL_SERVER) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("TLS Web Server Authentication", -1));
	}
	if (usage & XKU_SSL_CLIENT) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("TLS Web Client Authentication", -1));
	}
	if (usage & XKU_SMIME) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("E-mail Protection", -1));
	}
	if (usage & XKU_CODE_SIGN) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Code Signing", -1));
	}
	if (usage & XKU_SGC) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("SGC", -1));
	}
	if (usage & XKU_OCSP_SIGN) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("OCSP Signing", -1));
	}
	if (usage & XKU_TIMESTAMP) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Time Stamping", -1));
	}
	if (usage & XKU_DVCS ) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("DVCS", -1));
	}
	if (usage & XKU_ANYEKU) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Any Extended Key Usage", -1));
	}
    }
    LAPPEND_LIST(interp, certPtr, "extendedKeyUsage", listPtr);

    /* CRL Distribution Points identifies where CRL information can be obtained.
	RFC 5280 section 4.2.1.13*/
    listPtr = Tcl_NewListObj(0, NULL);
    if (crl = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL)) {
	Tcl_Obj *namesPtr = Tcl_NewListObj(0, NULL);

	for (int i=0; i < sk_DIST_POINT_num(crl); i++) {
	    DIST_POINT *dp = sk_DIST_POINT_value(crl, i);
	    DIST_POINT_NAME *distpoint = dp->distpoint;

	    if (distpoint->type == 0) {
		/* fullname GENERALIZEDNAME */
		for (int j = 0; j < sk_GENERAL_NAME_num(distpoint->name.fullname); j++) {
		    GENERAL_NAME *gen = sk_GENERAL_NAME_value(distpoint->name.fullname, j);
		    int type;
		    ASN1_STRING *uri = GENERAL_NAME_get0_value(gen, &type);
		    if (type == GEN_URI) {
			Tcl_ListObjAppendElement(interp, listPtr,
			    Tcl_NewStringObj((char*)ASN1_STRING_get0_data(uri), ASN1_STRING_length(uri)));
		    }
		}
	    } else if (distpoint->type == 1) {
		/* relativename X509NAME */
		STACK_OF(X509_NAME_ENTRY) *sk_relname = distpoint->name.relativename;
		for (int j = 0; j < sk_X509_NAME_ENTRY_num(sk_relname); j++) {
		    X509_NAME_ENTRY *e = sk_X509_NAME_ENTRY_value(sk_relname, j);
		    ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
		    Tcl_ListObjAppendElement(interp, listPtr,
			Tcl_NewStringObj((char*)ASN1_STRING_data(d), ASN1_STRING_length(d)));
		}
	    }
	}
	CRL_DIST_POINTS_free(crl);
    }
    LAPPEND_LIST(interp, certPtr, "crlDistributionPoints", listPtr);

    /* Freshest CRL extension */
    if (xflags & EXFLAG_FRESHEST) {
    }

    /* Authority Information Access indicates how to access info and services
	for the certificate issuer. RFC 5280 section 4.2.2.1, NID_info_access */
    /* Get On-line Certificate Status Protocol (OSCP) URL */
    listPtr = Tcl_NewListObj(0, NULL);
    if (ocsp = X509_get1_ocsp(cert)) {
	for (int i = 0; i < sk_OPENSSL_STRING_num(ocsp); i++) {
	    Tcl_ListObjAppendElement(interp, listPtr,
		Tcl_NewStringObj(sk_OPENSSL_STRING_value(ocsp, i), -1));
	}
	X509_email_free(ocsp);
    }
    LAPPEND_LIST(interp, certPtr, "ocsp", listPtr);

    /* CA Issuers URL caIssuers */

    /* Subject Information Access - RFC 5280 section 4.2.2.2, NID_sinfo_access */

    /* Certificate Alias. If uses a PKCS#12 structure, alias will reflect the
	friendlyName attribute (RFC 2985). */
    len = 0;
    LAPPEND_STR(interp, certPtr, "alias", X509_alias_get0(cert, &len), len);

    /* Certificate and dump all data */
    {
	char certStr[CERT_STR_SIZE];

	/* Get certificate */
	len = BIO_to_Buffer(PEM_write_bio_X509(bio, cert), bio, certStr, CERT_STR_SIZE);
	LAPPEND_STR(interp, certPtr, "certificate", certStr, len);

	/* Get all cert info */
	len = BIO_to_Buffer(X509_print_ex(bio, cert, flags, 0), bio, certStr, CERT_STR_SIZE);
	LAPPEND_STR(interp, certPtr, "all", certStr, len);
    }

    BIO_free(bio);
    return certPtr;
}
