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
 * BIO to Buffer
 */
int BIO_to_Buffer(int result, BIO *bio, void *buffer) {
    int len = 0;

    if (result) {
	len = BIO_read(bio, buffer, min(BIO_pending(bio), BUFSIZ));
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
    Tcl_Obj *certPtr = Tcl_NewListObj(0, NULL);
    BIO *bio = BIO_new(BIO_s_mem());
    int mdnid, pknid, bits, len;
    uint32_t xflags, usage;
    char buffer[BUFSIZ];
    unsigned char md[EVP_MAX_MD_SIZE];
    STACK_OF(GENERAL_NAME) *san;
    STACK_OF(DIST_POINT) *crl;
    STACK_OF(OPENSSL_STRING) *ocsp;
    unsigned long flags = XN_FLAG_RFC2253 | ASN1_STRFLGS_UTF8_CONVERT;
    flags &= ~ASN1_STRFLGS_ESC_MSB;

    if (bio == NULL || certPtr == NULL) {
	return NULL;
    }

    /* Signature algorithm and value - RFC 5280 section 4.1.1.2 and 4.1.1.3 */
    /* The signatureAlgorithm field contains the identifier for the cryptographic algorithm
	used by the CA to sign this certificate. The signatureValue field contains a digital
	signature computed upon the ASN.1 DER encoded tbsCertificate. */
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

    /* Version of the encoded certificate - RFC 5280 section 4.1.2.1 */
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("version", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewLongObj(X509_get_version(cert)+1));

    /* Unique number assigned by CA to certificate - RFC 5280 section 4.1.2.2 */
    len = BIO_to_Buffer(i2a_ASN1_INTEGER(bio, X509_get0_serialNumber(cert)), bio, buffer);
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("serialNumber", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(buffer, len));

    /* Signature algorithm used by the CA to sign the certificate. Must match
	signatureAlgorithm. RFC 5280 section 4.1.2.3 */
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("signature", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(OBJ_nid2ln(X509_get_signature_nid(cert)),-1));

    /* The issuer identifies the entity that has signed and issued the certificate.
	RFC 5280 section 4.1.2.4 */
    len = BIO_to_Buffer(X509_NAME_print_ex(bio, X509_get_issuer_name(cert), 0, flags), bio, buffer);
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("issuer", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(buffer, len));

    /* Certificate validity period is the time interval during which the CA
	warrants that it will maintain information about the status of the certificate.
	RFC 5280 section 4.1.2.5 */
    /* Get Validity - Not Before */
    len = BIO_to_Buffer(ASN1_TIME_print(bio, X509_get0_notBefore(cert)), bio, buffer);
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("notBefore", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(buffer, len));

    /* Get Validity - Not After */
    len = BIO_to_Buffer(ASN1_TIME_print(bio, X509_get0_notAfter(cert)), bio, buffer);
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("notAfter", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(buffer, len));

    /* The subject identifies the entity associated with the public key stored
	in the subject public key field. RFC 5280 section 4.1.2.6 */
    len = BIO_to_Buffer(X509_NAME_print_ex(bio, X509_get_subject_name(cert), 0, flags), bio, buffer);
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("subject", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(buffer, len));

    /* SHA1 Fingerprint of cert - DER representation */
    if (X509_digest(cert, EVP_sha1(), md, &len)) {
    len = String_to_Hex(md, len, buffer, BUFSIZ);
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("sha1_hash", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(buffer, len));
    }

    /* SHA256 Fingerprint of cert - DER representation */
    if (X509_digest(cert, EVP_sha256(), md, &len)) {
    len = String_to_Hex(md, len, buffer, BUFSIZ);
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("sha256_hash", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(buffer, len));
    }

    /* Subject Public Key Info specifies the public key and identifies the
	algorithm with which the key is used. RFC 5280 section 4.1.2.7 */
    if (X509_get_signature_info(cert, &mdnid, &pknid, &bits, &xflags) == 1) {
	ASN1_BIT_STRING *key;
	unsigned int n;

	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("signingDigest", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(OBJ_nid2ln(mdnid),-1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("publicKeyAlgorithm", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(OBJ_nid2ln(pknid),-1));
	/* Effective security bits */
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("bits", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewIntObj(bits));

	key = X509_get0_pubkey_bitstr(cert);
	len = String_to_Hex(key->data, key->length, buffer, BUFSIZ);
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("publicKey", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(buffer, len));

	if (X509_pubkey_digest(cert, EVP_get_digestbynid(pknid), md, &n)) {
	    len = String_to_Hex(md, (int)n, buffer, BUFSIZ);
	} else {
	    len = 0;
	}
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("publicKeyHash", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(buffer, len));
	

	/* Check if cert was issued by CA cert issuer or self signed */
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("self_signed", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewBooleanObj(X509_check_issued(cert, cert) == X509_V_OK));

	if (X509_digest(cert, EVP_get_digestbynid(mdnid), md, &n)) {
	    len = String_to_Hex(md, (int)n, buffer, BUFSIZ);
	} else {
	    len = 0;
	}
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("signatureHash", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(buffer, len));
    }

    xflags = X509_get_extension_flags(cert);
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("extension_flags", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewIntObj(xflags));

	/* Check if cert was issued by CA cert issuer or self signed */
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("selfIssued", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewBooleanObj(xflags & EXFLAG_SI));

	/* Check if cert was issued by CA cert issuer or self signed */
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("selfSigned", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewBooleanObj(xflags & EXFLAG_SS));


    /* Unique Ids -  The unique identifiers are present in the certificate to handle the
	possibility of reuse of subject and/or issuer names over time. RFC 5280 section 4.1.2.8 */
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
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("num_extensions", -1));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewIntObj(len));
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("extensions", -1));
    if (len > 0) {
	Tcl_Obj *extsPtr = Tcl_NewListObj(0, NULL);
	const STACK_OF(X509_EXTENSION) *exts;
	exts = X509_get0_extensions(cert);

	for (int i=0; i < len; i++) {
	    X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
	    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
	    unsigned nid2 = OBJ_obj2nid(obj);
	    Tcl_ListObjAppendElement(interp, extsPtr, Tcl_NewStringObj(OBJ_nid2ln(nid2), -1));
	}
	Tcl_ListObjAppendElement(interp, certPtr, extsPtr);
    } else {
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("", -1));
    }

    /* Authority Key Identifier (AKI) of a certificate should be the Subject Key
	Identifier (SKI) of its signer (the CA). RFC 5280 section 4.2.1.1, NID_authority_key_identifier */
    {
	ASN1_OCTET_STRING *astring = X509_get0_authority_key_id(cert);
	if (astring != NULL) {
	    len = String_to_Hex((char *)ASN1_STRING_get0_data(astring), ASN1_STRING_length(astring), buffer, BUFSIZ);
	} else {
	    len = 0;
	}
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("authorityKeyIdentifier", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(buffer, len));
    }

    /* Subject Key Identifier (SKI) provides a means of identifying certificates
	that contain a particular public key. RFC 5280 section 4.2.1.2, NID_subject_key_identifier */
    {
	ASN1_OCTET_STRING *astring = X509_get0_subject_key_id(cert);
	if (astring != NULL) {
	    len = String_to_Hex((char *)ASN1_STRING_get0_data(astring), ASN1_STRING_length(astring), buffer, BUFSIZ);
	} else {
	    len = 0;
	}
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("subjectKeyIdentifier", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(buffer, len));
    }

    /* Key usage extension defines the purpose (e.g., encipherment, signature, certificate
	signing) of the key contained in the certificate. RFC 5280 section 4.2.1.3, NID_key_usage */
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("keyUsage", -1));
    usage = X509_get_key_usage(cert);
    if (xflags & EXFLAG_KUSAGE && usage < 0xffffff) {
	Tcl_Obj *tmpPtr = Tcl_NewListObj(0, NULL);
	if (usage & KU_DIGITAL_SIGNATURE) {
	    Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj("Digital Signature", -1));
	}
	if (usage & KU_NON_REPUDIATION) {
	    Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj("Non-Repudiation", -1));
	}
	if (usage & KU_KEY_ENCIPHERMENT) {
	    Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj("Key Encipherment", -1));
	}
	if (usage & KU_DATA_ENCIPHERMENT) {
	    Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj("Data Encipherment", -1));
	}
	if (usage & KU_KEY_AGREEMENT) {
	    Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj("Key Agreement", -1));
	}
	if (usage & KU_KEY_CERT_SIGN) {
	    Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj("Certificate Signing", -1));
	}
	if (usage & KU_CRL_SIGN) {
	    Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj("CRL Signing", -1));
	}
	if (usage & KU_ENCIPHER_ONLY) {
	    Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj("Encipher Only", -1));
	}
	if (usage & KU_DECIPHER_ONLY) {
	    Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj("Decipher Only", -1));
	}
	Tcl_ListObjAppendElement(interp, certPtr, tmpPtr);
    } else {
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("", -1));
    }


    /* Purpose */
    {
	char *purpose = NULL;

	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("purpose", -1));
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
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(purpose, -1));
    }

    {
	Tcl_Obj *purpPtr = Tcl_NewListObj(0, NULL);
	for (int j = 0; j < X509_PURPOSE_get_count(); j++) {
	    X509_PURPOSE *ptmp = X509_PURPOSE_get0(j);
	    Tcl_Obj *tmpPtr = Tcl_NewListObj(0, NULL);

	    for (int i = 0; i < 2; i++) {
		int idret = X509_check_purpose(cert, X509_PURPOSE_get_id(ptmp), i);
		Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj(i ? "CA" : "nonCA", -1));
		Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj(idret == 1 ? "Yes" : "No", -1));
	    }
	    Tcl_ListObjAppendElement(interp, purpPtr, Tcl_NewStringObj(X509_PURPOSE_get0_name(ptmp), -1));
	    Tcl_ListObjAppendElement(interp, purpPtr, tmpPtr);
	}
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("certificatePurpose", -1));
	Tcl_ListObjAppendElement(interp, certPtr, purpPtr);
    }

    /* Certificate Policies - indicates the issuing CA considers its issuerDomainPolicy
	equivalent to the subject CA's subjectDomainPolicy. RFC 5280 section 4.2.1.4, NID_certificate_policies */
    if (xflags & EXFLAG_INVALID_POLICY) {
	/* Reject cert */
    }

    /* Policy Mappings - RFC 5280 section 4.2.1.5, NID_policy_mappings */

    /* Subject Alternative Name (SAN) contains additional URLs, DNS name, or IP
	addresses bound to certificate. RFC 5280 section 4.2.1.6, NID_subject_alt_name */
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("subjectAltName", -1));
    san = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (san) {
	Tcl_Obj *namesPtr = Tcl_NewListObj(0, NULL);

	for (int i=0; i < sk_GENERAL_NAME_num(san); i++) {
	    const GENERAL_NAME *name = sk_GENERAL_NAME_value(san, i);

	    if (name && bio) {
		if (GENERAL_NAME_print(bio, name)) {
		    int n = BIO_read(bio, buffer, min(BIO_pending(bio), BUFSIZ));
		    buffer[max(n, 0)] = 0;
		    (void)BIO_flush(bio);
		    Tcl_ListObjAppendElement(interp, namesPtr, Tcl_NewStringObj(buffer, n));
		}
	    }
	}
	sk_GENERAL_NAME_pop_free(san, GENERAL_NAME_free);
	Tcl_ListObjAppendElement(interp, certPtr, namesPtr);
    } else {
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("", -1));
    }

    /* Issuer Alternative Name (issuerAltName) is used to associate Internet
	style identities with the certificate issuer. RFC 5280 section 4.2.1.7, NID_issuer_alt_name */
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("issuerAltName", -1));
    san = X509_get_ext_d2i(cert, NID_issuer_alt_name, NULL, NULL);
    if (san) {
	Tcl_Obj *namesPtr = Tcl_NewListObj(0, NULL);

	for (int i=0; i < sk_GENERAL_NAME_num(san); i++) {
	    const GENERAL_NAME *name = sk_GENERAL_NAME_value(san, i);

	    if (name && bio) {
		if (GENERAL_NAME_print(bio, name)) {
		    int n = BIO_read(bio, buffer, min(BIO_pending(bio), BUFSIZ));
		    buffer[max(n, 0)] = 0;
		    (void)BIO_flush(bio);
		    Tcl_ListObjAppendElement(interp, namesPtr, Tcl_NewStringObj(buffer, n));
		}
	    }
	}
	sk_GENERAL_NAME_pop_free(san, GENERAL_NAME_free);
	Tcl_ListObjAppendElement(interp, certPtr, namesPtr);
    } else {
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("", -1));
    }

    /* Subject Directory Attributes provides identification attributes (e.g., nationality)
	of the subject. RFC 5280 section 4.2.1.8 (subjectDirectoryAttributes) */

    /* Basic Constraints identifies whether the subject of the cert is a CA and
	the max depth of valid cert paths that include this cert.
	RFC 5280 section 4.2.1.9 (basicConstraints, NID_basic_constraints) */
    if (xflags & EXFLAG_BCONS) {
	long len2 = X509_get_pathlen(cert);
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("pathLen", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewLongObj(len2));
    }
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("basicConstraintsCA", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewBooleanObj(xflags & EXFLAG_CA));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("basicConstraintsCritical", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewBooleanObj(xflags & EXFLAG_CRITICAL));

    /* Name Constraints is only used in CA certs to indicate a name space within
	which all subject names in subsequent certificates in a certification path
	MUST be located. RFC 5280 section 4.2.1.10, NID_name_constraints */

    /* Policy Constraints is only used in CA certs to limit the length of a
	cert chain that may be issued from that CA. RFC 5280 section 4.2.1.11, NID_policy_constraints */

    /* Extended Key Usage indicates one or more purposes for which the certified
	public key may be used, in addition to or in place of the basic purposes.
	RFC 5280 section 4.2.1.12, NID_ext_key_usage */
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("extendedKeyUsage", -1));
    if (xflags & EXFLAG_XKUSAGE) {
    usage = X509_get_extended_key_usage(cert);
	Tcl_Obj *tmpPtr = Tcl_NewListObj(0, NULL);
	if (usage & XKU_SSL_SERVER) {
	    Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj("TLS Web Server Authentication", -1));
	}
	if (usage & XKU_SSL_CLIENT) {
	    Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj("TLS Web Client Authentication", -1));
	}
	if (usage & XKU_SMIME) {
	    Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj("E-mail Protection", -1));
	}
	if (usage & XKU_CODE_SIGN) {
	    Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj("Code Signing", -1));
	}
	if (usage & XKU_SGC) {
	    Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj("SGC", -1));
	}
	if (usage & XKU_OCSP_SIGN) {
	    Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj("OCSP Signing", -1));
	}
	if (usage & XKU_TIMESTAMP) {
	    Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj("Time Stamping", -1));
	}
	if (usage & XKU_DVCS ) {
	    Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj("DVCS", -1));
	}
	if (usage & XKU_ANYEKU) {
	    Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj("Any Extended Key Usage", -1));
	}
	Tcl_ListObjAppendElement(interp, certPtr, tmpPtr);
    } else {
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("", -1));
    }

    /* CRL Distribution Points extension identifies how CRL information is
	obtained. RFC 5280 section 4.2.1.13*/
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("crlDistributionPoints", -1));
    crl = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
    if (crl) {
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
			Tcl_ListObjAppendElement(interp, namesPtr,
			    Tcl_NewStringObj((char*)ASN1_STRING_get0_data(uri), ASN1_STRING_length(uri)));
		    }
		}
	    } else if (distpoint->type == 1) {
		/* relativename X509NAME */
		STACK_OF(X509_NAME_ENTRY) *sk_relname = distpoint->name.relativename;
		for (int j = 0; j < sk_X509_NAME_ENTRY_num(sk_relname); j++) {
		    X509_NAME_ENTRY *e = sk_X509_NAME_ENTRY_value(sk_relname, j);
		    ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
		    Tcl_ListObjAppendElement(interp, namesPtr, Tcl_NewStringObj((char*)ASN1_STRING_data(d), ASN1_STRING_length(d)));
		}
	    }
	}
	CRL_DIST_POINTS_free(crl);
	Tcl_ListObjAppendElement(interp, certPtr, namesPtr);
    } else {
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("", -1));
    }

    /* Freshest CRL extension */
    if (xflags & EXFLAG_FRESHEST) {
    }

    /* Authority Information Access indicates how to access info and services
	for the certificate issuer. THis includes on-line validation services
	and CA policy data. RFC 5280 section 4.2.2.1, NID_info_access */
    /* Get On-line Certificate Status Protocol (OSCP) URL */
    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("ocsp", -1));
    ocsp = X509_get1_ocsp(cert);
    if (ocsp) {
	Tcl_Obj *urlsPtr = Tcl_NewListObj(0, NULL);

	for (int i = 0; i < sk_OPENSSL_STRING_num(ocsp); i++) {
	    Tcl_ListObjAppendElement(interp, urlsPtr,
		Tcl_NewStringObj(sk_OPENSSL_STRING_value(ocsp, i), -1));
	}

	X509_email_free(ocsp);
	/* sk_OPENSSL_STRING_free(ocsp); */
	Tcl_ListObjAppendElement(interp, certPtr, urlsPtr);
    } else {
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("", -1));
    }

    /* CA Issuers URL caIssuers */

    /* Subject Information Access - RFC 5280 section 4.2.2.2, NID_sinfo_access */

    /* Certificate Alias as UTF-8 string. If uses a PKCS#12 structure, alias
	will reflect the friendlyName attribute (RFC 2985). */
    {
	unsigned char *bstring;
	len = 0;
	bstring = X509_alias_get0(cert, &len);
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("alias", -1));
	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj((char *)bstring, len));
    }

    /* All data */
    {
	char certStr[CERT_STR_SIZE];
	len = 0;

	/* Get certificate */
	if (PEM_write_bio_X509(bio, cert)) {
	    len = BIO_read(bio, certStr, min(BIO_pending(bio), CERT_STR_SIZE));
	    (void)BIO_flush(bio);
	    if (len < 0) {len = 0;}
	    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("certificate", -1));
	    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(certStr, len));
	}

	/* Get all cert info */
	if (X509_print_ex(bio, cert, flags, 0)) {
	    len = BIO_read(bio, certStr, min(BIO_pending(bio), CERT_STR_SIZE));
	    (void)BIO_flush(bio);
	    if (len < 0) {len = 0;}
	    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("all", -1));
	    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj(certStr, len));
	}
    }

    BIO_free(bio);
    return certPtr;
}
