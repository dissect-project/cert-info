"""
Checks run on every certificate of a chain, following Firefox: supported
extensions, signature, validity period, the issuer's right to issue it,
supported key and signature algorithms, and for the leaf its hostname,
purpose, revocation and OCSP Must-Staple. The NIST status of the algorithms
is reported too, for information.
"""

import ipaddress
import subprocess
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import SignatureAlgorithmOID

from src.chain import certificate_rules as rules
from src.chain.certificate_rules import extension
from src.chain.names import PRESENTED, InvalidName, is_valid_dns_id, match_dns_id
from src.chain.signatures import UnsupportedSignature, verify_signature
from src.validation import revocation
from src.validation.nist.parser import CSVParser

# Certificate IDs
LEAF = "Leaf Certificate"
INTERMEDIATE = "Intermediate Certificate"
ROOT = "Root CA Certificate"

# Issues
INCOMPLETE_CHAIN    = "Certificate chain is incomplete"
SIGNATURE_FAILED    = "Signature verification failed"
HOSTNAME_MISMATCH   = "Hostname mismatch"
EXPIRED             = "Certificate expired"
NOT_YET_VALID       = "Certificate not yet valid"
NOT_VALID_CA        = rules.NOT_VALID_CA
NO_CA_INFO          = rules.NO_CA_INFO
ISSUER_KEY_USAGE    = rules.ISSUER_KEY_USAGE
ISSUER_EKU          = rules.ISSUER_EKU
ISSUER_PATH_LENGTH  = rules.ISSUER_PATH_LENGTH
NOT_SERVER_AUTH     = "Certificate is not valid for TLS server authentication (Extended Key Usage)"
NOT_TLS_KEY_USAGE   = "Certificate key is not allowed for TLS (Key Usage)"
NIST_DISALLOWED     = "no longer allowed for applying cryptographic protection"
NIST_DEPRECATED     = "may be used, but user must accept security risks"
NIST_LEGACY         = "may be used only to process already protected information"
UNKNOWN_HASH        = "Could not determine signature hash algorithm."
UNKNOWN_SIGNATURE   = "Could not determine signature algorithm"
UNKNOWN_KEY         = "Could not determine public key algorithm"

# Warnings
WILDCARD_USAGE      = "Certificate uses wildcard domain"
NO_COMMON_NAME      = "Certificate has no Common Name (CN)"
DNSSEC_FAILED       = "DNSSEC validation failed."
DNSSEC_UNAVAILABLE  = "DNSSEC could not be checked."

# EdDSA signatures have no separate hash: the hash is part of the algorithm
# (SHA-512 for Ed25519, SHAKE256 for Ed448), which NIST approves.
EDDSA_SIGNATURES = {SignatureAlgorithmOID.ED25519, SignatureAlgorithmOID.ED448}

# NIST status -> issue suffix. These are reported for information: whether
# an algorithm is acceptable is decided by Firefox's rules
# (src/chain/certificate_rules.py).
NIST_STATUS = {
    "Disallowed": NIST_DISALLOWED,
    "Deprecated": NIST_DEPRECATED,
    "Legacy": NIST_LEGACY,
}


class CertificateValidator:
    """Validate one certificate of a chain."""

    @staticmethod
    def validate(domain: str, cert: x509.Certificate, issuer: x509.Certificate | None,
                 cert_id: str, position: int = 0, issuer_is_root: bool = False,
                 stapled_ocsp: bytes | None = None,
                 revocation_outcome: dict | None = None,
                 dnssec_warnings: list | None = None) -> tuple[bool, list, list]:
        """
        Run all checks on a certificate.

        Args:
            domain (str): The domain being analysed.
            cert (x509.Certificate): The certificate to check.
            issuer (x509.Certificate): The next certificate in the chain (the
                certificate itself for a root), or None if the chain stops here.
            cert_id (str): LEAF, INTERMEDIATE or ROOT.
            position (int): Position in the chain (0 for the leaf).
            issuer_is_root (bool): Whether the issuer is the chain's root.
            stapled_ocsp (bytes): The OCSP response stapled by the server
                (only used for the leaf).
            revocation_outcome (dict): Receives details of the leaf's
                revocation check (see revocation.check_leaf_revocation).
            dnssec_warnings (list): The result of check_dnssec(domain), if it
                was already run (e.g. in parallel); otherwise it is run here.

        Returns:
            tuple: (valid, issues, warnings). Some issues, such as the NIST
            status of algorithms, are reported without making the
            certificate invalid.
        """
        issues = []
        warnings = []
        passed = []

        if cert_id == LEAF:
            if dnssec_warnings is None:
                _check_dnssec(domain, warnings)
            else:
                warnings.extend(dnssec_warnings)
        passed.append(_report(rules.extension_problems(cert), issues))
        if issuer is None:
            issues.append(INCOMPLETE_CHAIN)
            passed.append(False)
        else:
            passed.append(_check_signature(cert, issuer, issues))
            # Every certificate's issuer, including the leaf's, must be
            # allowed to issue it. A root is checked as a CA too; its path
            # length is checked with the certificate below it.
            self_issued = issuer is cert
            passed.append(_report(rules.issuer_problems(
                issuer, 0 if self_issued else position,
                is_trust_anchor=self_issued or issuer_is_root), issues))
        passed.append(_check_validity_period(cert, issues))
        if cert_id == LEAF:
            passed.append(_check_hostname(cert, domain, issues, warnings))
            passed.append(_check_server_auth(cert, issues))
            passed.append(_check_tls_key_usage(cert, issues))
            passed.append(_report(rules.leaf_problems(cert), issues))
            passed.append(revocation.check_must_staple(cert, stapled_ocsp, issues))
            if issuer is not None:
                passed.append(revocation.check_leaf_revocation(
                    cert, issuer, issues, warnings, stapled_ocsp, outcome=revocation_outcome))
        elif not cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
            warnings.append(NO_COMMON_NAME)
        passed.append(_report(rules.key_problems(cert), issues))
        # A root's self-signature is not relied upon (trust comes from the
        # trust store), so its algorithm is not checked.
        if cert_id != ROOT:
            passed.append(_report(rules.signature_problems(cert), issues))
            _report_hash_strength(cert, issues)
        _report_key_strength(cert, issues)

        return all(passed), issues, warnings


def _report(problems: list, issues: list) -> bool:
    """Add problems to the issues; True if there are none."""
    issues.extend(problems)
    return not problems


def check_dnssec(domain: str) -> list:
    """The DNSSEC warnings for a domain (see _check_dnssec)."""
    warnings = []
    _check_dnssec(domain, warnings)
    return warnings


def _check_dnssec(domain: str, warnings: list) -> None:
    """Warn if the domain's DNS answer is not DNSSEC-validated (AD flag)."""
    try:
        result = subprocess.run(["dig", "@8.8.8.8", "+dnssec", "+tries=2", "+time=5", domain],
                                capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        warnings.append(DNSSEC_UNAVAILABLE)
        return
    flags = [line for line in result.stdout.splitlines() if ";; flags:" in line]
    if result.returncode != 0 or not flags:
        warnings.append(DNSSEC_UNAVAILABLE)
    elif " ad" not in flags[0].split(";")[2]:
        warnings.append(DNSSEC_FAILED)


def _check_signature(cert: x509.Certificate, issuer: x509.Certificate, issues: list) -> bool:
    """
    Verify that the issuer signed the certificate. Supports RSA (PKCS#1 v1.5
    and PSS), ECDSA, Ed25519, Ed448 and DSA, with any hash including SHA-1
    (whether Firefox accepts the algorithm is checked separately).
    """
    try:
        verify_signature(cert, issuer)
        return True
    except InvalidSignature:
        issues.append(SIGNATURE_FAILED)
    except UnsupportedSignature:
        issues.append(UNKNOWN_SIGNATURE)
    return False


def _check_validity_period(cert: x509.Certificate, issues: list) -> bool:
    """Check that the current time is within the certificate's validity period."""
    now = datetime.now(timezone.utc)
    if cert.not_valid_after_utc < now:
        issues.append(EXPIRED)
        return False
    if cert.not_valid_before_utc > now:
        issues.append(NOT_YET_VALID)
        return False
    return True


def _check_server_auth(cert: x509.Certificate, issues: list) -> bool:
    """Check that the leaf may be used for TLS server authentication."""
    if rules.allows_server_auth(cert):
        return True
    issues.append(NOT_SERVER_AUTH)
    return False


def _check_tls_key_usage(cert: x509.Certificate, issues: list) -> bool:
    """
    Check that the leaf's Key Usage (if present) allows a TLS key exchange, as
    Firefox requires: digitalSignature ((EC)DHE), keyEncipherment (RSA) or
    keyAgreement ((EC)DH).
    """
    key_usage = extension(cert, x509.KeyUsage)
    if key_usage is None or key_usage.digital_signature or key_usage.key_encipherment \
            or key_usage.key_agreement:
        return True
    issues.append(NOT_TLS_KEY_USAGE)
    return False


def _matches(name: str, hostname: str) -> tuple[bool, bool]:
    """
    Match a certificate DNS name against a hostname as mozilla::pkix does
    (src/chain/names.py): case-insensitively, a wildcard only as the whole
    first label, with two labels after it, matching exactly one label.

    Returns:
        tuple: (matches, through_wildcard)
    """
    try:
        matches = match_dns_id(name, hostname)
    except InvalidName:
        return False, False
    return matches, matches and name.startswith("*.")


def _check_hostname(cert: x509.Certificate, expected: str, issues: list, warnings: list) -> bool:
    """
    Check that the certificate is valid for the hostname, as Firefox does:
    only the Subject Alternative Name is used (never the CN). DNS names are
    compared with a DNS hostname, IP addresses with an IP address. Names are
    tried in order; an invalid DNS name stops the search.
    """
    try:
        ip = ipaddress.ip_address(expected)
    except ValueError:
        ip = None
    san = extension(cert, x509.SubjectAlternativeName) or []
    for name in san:
        if ip is None and isinstance(name, x509.DNSName):
            if not is_valid_dns_id(name.value, PRESENTED, allow_wildcards=True):
                break
            matches, wildcard = _matches(name.value, expected)
            if matches:
                if wildcard:
                    warnings.append(WILDCARD_USAGE)
                return True
        elif ip is not None and isinstance(name, x509.IPAddress) and name.value == ip:
            return True
    issues.append(HOSTNAME_MISMATCH)
    return False


def _report_hash_strength(cert: x509.Certificate, issues: list) -> None:
    """Report the signature hash if NIST no longer considers it acceptable."""
    if cert.signature_algorithm_oid in EDDSA_SIGNATURES:
        return
    try:
        status = CSVParser.get_hash_status(cert.signature_hash_algorithm)
    except Exception:
        issues.append(UNKNOWN_HASH)
        return
    if status in NIST_STATUS:
        issues.append("Hash " + NIST_STATUS[status])


def _report_key_strength(cert: x509.Certificate, issues: list) -> None:
    """Report the public key if NIST no longer considers it acceptable."""
    try:
        status, key_issues = CSVParser.get_key_status(cert.public_key())
    except Exception:
        issues.append(UNKNOWN_KEY)
        return
    if status in NIST_STATUS:
        issues.append("Key " + NIST_STATUS[status])
    issues.extend(key_issues)
