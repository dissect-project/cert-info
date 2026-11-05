"""
The checks Firefox (mozilla::pkix) applies to each certificate of a chain,
shared by the path builder and the certificate validator.

Each function returns a list of problems (empty if the certificate passes),
so the validator can report them and the path builder can skip candidates
that have any.
"""

from datetime import datetime

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, ObjectIdentifier

from src.chain import der

DER = Encoding.DER

# Problems
MALFORMED_EXTENSIONS = "Certificate has malformed or duplicate extensions"
UNKNOWN_CRITICAL_EXTENSION = "Certificate has a critical extension Firefox does not support"
UNSUPPORTED_KEY = "Public key type is not supported by Firefox"
UNSUPPORTED_CURVE = "Elliptic curve is not supported by Firefox (only P-256, P-384 and P-521)"
RSA_KEY_TOO_SMALL = "RSA key is shorter than {bits} bits"
SHA1_SIGNATURE = "Signed with SHA-1, which Firefox rejects"
UNSUPPORTED_SIGNATURE = "Signature algorithm is not supported by Firefox"
SIGNATURE_ALGORITHM_MISMATCH = "Signature algorithm differs inside and outside the signed part of the certificate"
NOT_VALID_CA = "Issuer is not a valid CA"
NO_CA_INFO = "Certificate has no information about being a valid CA"
ISSUER_KEY_USAGE = "Issuer is not allowed to sign certificates (Key Usage)"
ISSUER_EKU = "Issuer is not allowed to issue TLS server certificates (Extended Key Usage)"
ISSUER_PATH_LENGTH = "Issuer's path length constraint is exceeded"
LEAF_IS_CA = "Certificate is a CA certificate and cannot be used by a server"
LEAF_OCSP_SIGNING = "Certificate is also an OCSP signing certificate, which Firefox rejects"

# Firefox's minimum RSA key sizes. Ordinary chains are first built with 2048
# bits, then with 1024 for compatibility; EV chains need 2048.
MIN_RSA_BITS = 2048
MIN_RSA_BITS_WEAK = 1024
SUPPORTED_CURVES = (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)
# Signature algorithms mozilla::pkix supports (pkixder.cpp,
# SignatureAlgorithmIdentifierValue): OID -> (key algorithm, digest).
# SHA-224 and MD5 are not supported; SHA-1 is parsed, then disabled.
SIGNATURE_ALGORITHMS = {
    "1.2.840.113549.1.1.11": ("RSA", "SHA-256"),
    "1.2.840.113549.1.1.12": ("RSA", "SHA-384"),
    "1.2.840.113549.1.1.13": ("RSA", "SHA-512"),
    "1.2.840.10045.4.3.2": ("ECDSA", "SHA-256"),
    "1.2.840.10045.4.3.3": ("ECDSA", "SHA-384"),
    "1.2.840.10045.4.3.4": ("ECDSA", "SHA-512"),
    "1.2.840.113549.1.1.5": ("RSA", "SHA-1"),
    "1.3.14.3.2.29": ("RSA", "SHA-1"),         # sha1WithRSASignature (OIW)
    "1.2.840.10045.4.1": ("ECDSA", "SHA-1"),
}
RSA_PSS = "1.2.840.113549.1.1.10"
# The only RSA-PSS parameters allowed (CA/Browser Forum Baseline
# Requirements): hash, MGF-1 with the same hash, salt as long as the hash
_PSS_PARAMETERS = {
    bytes.fromhex("3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108"
                  "300d06096086480165030402010500a203020120"): "SHA-256",
    bytes.fromhex("3034a00f300d06096086480165030402020500a11c301a06092a864886f70d010108"
                  "300d06096086480165030402020500a203020130"): "SHA-384",
    bytes.fromhex("3034a00f300d06096086480165030402030500a11c301a06092a864886f70d010108"
                  "300d06096086480165030402030500a203020140"): "SHA-512",
}
_NULL = b"\x05\x00"

# Extensions mozilla::pkix understands; any other critical extension makes
# the certificate unusable (pkixcert.cpp, BackCert::RememberExtension).
# Authority and Subject Key Identifiers are ignored, so they are not here.
TLS_FEATURE = ExtensionOID.TLS_FEATURE
_OCSP_NO_CHECK = ExtensionOID.OCSP_NO_CHECK
_NETSCAPE_CERT_TYPE = ObjectIdentifier("2.16.840.1.113730.1.1")
UNDERSTOOD_EXTENSIONS = {
    ExtensionOID.KEY_USAGE, ExtensionOID.SUBJECT_ALTERNATIVE_NAME, ExtensionOID.BASIC_CONSTRAINTS,
    ExtensionOID.NAME_CONSTRAINTS, ExtensionOID.CERTIFICATE_POLICIES, ExtensionOID.POLICY_CONSTRAINTS,
    ExtensionOID.EXTENDED_KEY_USAGE, ExtensionOID.INHIBIT_ANY_POLICY, ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
    TLS_FEATURE, ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS,
    ObjectIdentifier("1.3.6.1.5.5.7.1.3"),  # qcStatements
}


# Raised by cryptography for extensions it cannot parse
EXTENSION_ERRORS = (ValueError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType)


def extension(cert: x509.Certificate, extension_class):
    """The value of an extension, or None if it is absent or unreadable."""
    try:
        return cert.extensions.get_extension_for_class(extension_class).value
    except (x509.ExtensionNotFound, *EXTENSION_ERRORS):
        return None


def extension_problems(cert: x509.Certificate) -> list:
    """Extensions Firefox cannot process: the certificate is rejected outright."""
    try:
        extensions = cert.extensions
    except EXTENSION_ERRORS:
        return [MALFORMED_EXTENSIONS]
    oids = {ext.oid for ext in extensions}
    for ext in extensions:
        if not ext.critical or ext.oid in UNDERSTOOD_EXTENSIONS or ext.oid == _OCSP_NO_CHECK:
            continue
        if ext.oid == _NETSCAPE_CERT_TYPE and {ExtensionOID.BASIC_CONSTRAINTS,
                                               ExtensionOID.EXTENDED_KEY_USAGE} <= oids:
            continue
        return [UNKNOWN_CRITICAL_EXTENSION]
    return []


def key_problems(cert: x509.Certificate, min_rsa_bits: int = MIN_RSA_BITS_WEAK) -> list:
    """Firefox accepts RSA keys of at least min_rsa_bits and ECDSA keys on P-256/384/521."""
    try:
        key = cert.public_key()
    except (ValueError, UnsupportedAlgorithm):
        return [UNSUPPORTED_KEY]
    if isinstance(key, rsa.RSAPublicKey):
        return [RSA_KEY_TOO_SMALL.format(bits=min_rsa_bits)] if key.key_size < min_rsa_bits else []
    if isinstance(key, ec.EllipticCurvePublicKey):
        return [] if isinstance(key.curve, SUPPORTED_CURVES) else [UNSUPPORTED_CURVE]
    return [UNSUPPORTED_KEY]


def _signature_algorithm(algorithm_identifier: der.Element) -> tuple | None:
    """(key algorithm, digest) of an encoded AlgorithmIdentifier, or None if Firefox does not support it."""
    parts = der.children(algorithm_identifier.content)
    if not parts or parts[0].tag != 0x06:
        return None
    oid = der.decode_oid(parts[0].content)
    parameters = b"".join(part.encoded for part in parts[1:])
    if oid == RSA_PSS:
        digest = _PSS_PARAMETERS.get(parameters)
        return ("RSA-PSS", digest) if digest else None
    algorithm = SIGNATURE_ALGORITHMS.get(oid)
    # Other algorithms' parameters must be NULL or absent
    return algorithm if parameters in (b"", _NULL) else None


def signature_problems(cert: x509.Certificate) -> list:
    """
    Firefox's CheckSignatureAlgorithm: the signature algorithm must be RSA
    (PKCS#1 v1.5, or PSS with the standard parameters) or ECDSA with SHA-256,
    SHA-384 or SHA-512, and the same in the signed part of the certificate as
    outside it.
    """
    try:
        certificate, signature_algorithm = der.children(der.parse(cert.public_bytes(DER)).content)[:2]
        tbs_fields = der.children(certificate.content)
        if tbs_fields and tbs_fields[0].tag == 0xA0:       # [0] version
            tbs_fields = tbs_fields[1:]
        tbs_signature = tbs_fields[1]                      # after the serial number
    except (ValueError, IndexError):
        return [UNSUPPORTED_SIGNATURE]
    outer = _signature_algorithm(signature_algorithm)
    inner = _signature_algorithm(tbs_signature)
    if outer is None or inner is None:
        return [UNSUPPORTED_SIGNATURE]
    if outer != inner:
        return [SIGNATURE_ALGORITHM_MISMATCH]
    return [SHA1_SIGNATURE] if outer[1] == "SHA-1" else []


def allows_server_auth(cert: x509.Certificate) -> bool:
    """
    No Extended Key Usage, or one that lists TLS server authentication.
    Firefox ignores anyExtendedKeyUsage.
    """
    ekus = extension(cert, x509.ExtendedKeyUsage)
    return ekus is None or ExtendedKeyUsageOID.SERVER_AUTH in ekus


def issuer_problems(issuer: x509.Certificate, sub_cas_below: int, is_trust_anchor: bool) -> list:
    """
    Whether a certificate may issue the one below it (mozilla::pkix checks
    this on every CA, trust anchors included): Basic Constraints with cA
    (version 1 trust anchors are accepted without it), keyCertSign if Key
    Usage is present, TLS server authentication if Extended Key Usage is
    present, and the path length constraint.

    Args:
        issuer: The CA certificate.
        sub_cas_below: Number of intermediates between it and the leaf.
        is_trust_anchor: Whether it is a root of the trust store.
    """
    problems = []
    constraints = extension(issuer, x509.BasicConstraints)
    if constraints is None:
        if not (is_trust_anchor and issuer.version == x509.Version.v1):
            return [NO_CA_INFO]
    elif not constraints.ca:
        return [NOT_VALID_CA]
    key_usage = extension(issuer, x509.KeyUsage)
    if key_usage is not None and not key_usage.key_cert_sign:
        problems.append(ISSUER_KEY_USAGE)
    if not allows_server_auth(issuer):
        problems.append(ISSUER_EKU)
    if constraints is not None and constraints.path_length is not None \
            and sub_cas_below > constraints.path_length:
        problems.append(ISSUER_PATH_LENGTH)
    return problems


def leaf_problems(leaf: x509.Certificate) -> list:
    """A server certificate may not be a CA, nor assert OCSP signing."""
    problems = []
    constraints = extension(leaf, x509.BasicConstraints)
    if constraints is not None and constraints.ca:
        problems.append(LEAF_IS_CA)
    ekus = extension(leaf, x509.ExtendedKeyUsage)
    if ekus is not None and ExtendedKeyUsageOID.OCSP_SIGNING in ekus:
        problems.append(LEAF_OCSP_SIGNING)
    return problems


def is_within_validity(cert: x509.Certificate, now: datetime) -> bool:
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def tls_features(cert: x509.Certificate) -> bytes | None:
    """The encoded TLS Feature extension (e.g. OCSP Must-Staple), or None."""
    try:
        return cert.extensions.get_extension_for_oid(TLS_FEATURE).value.public_bytes()
    except (x509.ExtensionNotFound, *EXTENSION_ERRORS):
        return None


def inherits_tls_features(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    """A certificate must repeat the TLS Feature extension of its issuer, if it has one."""
    required = tls_features(issuer)
    return required is None or required == tls_features(child)
