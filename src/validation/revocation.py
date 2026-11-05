"""
Revocation checks, following Firefox (NSSCertDBTrustDomain::CheckRevocation).

Firefox only checks the revocation of CA certificates with OneCRL (see
src/chain/path_builder.py). For the leaf certificate, in order:

1. CRLite: Mozilla's compressed set of all revocations, built from the CAs'
   CRLs. When CRLite covers the certificate, its answer is final. cert-info
   cannot read the CRLite filters; it uses the same source instead, the
   certificate's CRL. A CRL that was downloaded and verified is final.
2. The OCSP response stapled by the server: "good" accepts the certificate,
   "revoked" rejects it. An expired response, a responder answering
   tryLater, a response signed by an unauthorised certificate or a response
   about another certificate is ignored; any other problem (bad signature,
   "unknown" status, malformed response, ...) rejects the certificate.
3. Certificates valid for less than 10 days are not checked further.
4. Firefox does not fetch OCSP for certificates that chain to a Mozilla root:
   it relies on CRLite. When no CRL could be used, cert-info asks the OCSP
   responder instead, as a stand-in for CRLite, and only a "revoked" answer
   counts.

Expired certificates are not checked (responders may forget them).
CRLs and OCSP responses are only used if their signature verifies with the
issuer's key (or, for OCSP, a responder certificate the issuer authorised,
which must pass Firefox's checks on certificates). A CRL that does not list
the certificate only proves it is not revoked if it is current and complete:
not expired, not a delta CRL, and not limited to CA certificates or to some
revocation reasons.
URLs come from certificates and are fetched with src/fetch/network.py, which
only reaches public addresses over http.
"""

import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import TLSFeatureType
from cryptography.x509.ocsp import (
    OCSPCertStatus, OCSPRequestBuilder, OCSPResponseStatus, load_der_ocsp_response,
)
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, SignatureAlgorithmOID

from src.chain import certificate_rules as rules
from src.chain.certificate_rules import EXTENSION_ERRORS, extension
from src.chain.signatures import UnsupportedSignature, is_signed_by, verify_signed_data
from src.fetch.cache import ExpiringCache
from src.fetch.network import FetchError, fetch
from src.trust.store import TrustStore

# Issues
CRL_REVOKED = "Certificate is revoked (found in CRL)"
OCSP_REVOKED = "Certificate is revoked (found in OCSP)"
STAPLED_OCSP_REVOKED = "Certificate is revoked (stapled OCSP response)"
STAPLED_OCSP_INVALID = "Stapled OCSP response is not acceptable: {reason}"
MUST_STAPLE_MISSING = "Certificate requires a stapled OCSP response (OCSP Must-Staple), but the server sent none"
# Warnings
NO_REVOCATION_INFO = "No CRL or OCSP information found in the certificate."
STAPLED_OCSP_IGNORED = "Stapled OCSP response ignored: {reason}"

# Firefox does not look further than the stapled response for certificates
# valid for less than this (security.pki.cert_short_lifetime_in_days)
SHORT_LIFETIME = timedelta(days=10)

# OCSP response time rules of mozilla::pkix (pkixocsp.cpp)
OCSP_SLOP = timedelta(days=1)
OCSP_MAX_LIFETIME = timedelta(days=10)
OCSP_NO_NEXT_UPDATE_LIFETIME = timedelta(days=1)

# Results of evaluate_ocsp
GOOD = "good"
REVOKED = "revoked"
UNKNOWN = "certificate status unknown"
OLD = "response has expired"
FUTURE = "response is dated in the future"
MALFORMED = "invalid OCSP response"
BAD_SIGNATURE = "response signature could not be verified"
INVALID_SIGNING_CERT = "response is signed by a certificate the issuer did not authorise"
NOT_FOR_CERTIFICATE = "response is for another certificate"
# Stapled responses Firefox tolerates (treated like no stapled response)
TOLERATED_STAPLED = {OLD, INVALID_SIGNING_CERT, NOT_FOR_CERTIFICATE, "responder answered TRY_LATER"}

# Downloaded CRLs and OCSP responses are kept until their next update, but
# no longer than this, so that a revocation published early (before the next
# update) is seen within this delay. 0 disables the cache.
CACHE_MAX_AGE = timedelta(seconds=int(os.environ.get("CERTINFO_REVOCATION_CACHE_SECONDS", "3600")))
_crl_cache = ExpiringCache(max_bytes=200 * 1024 * 1024)
_ocsp_cache = ExpiringCache(max_bytes=20 * 1024 * 1024)

SCT_OCSP_EXTENSION = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.5")
_HASHES = {"sha1": hashes.SHA1, "sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}


def check_leaf_revocation(cert: x509.Certificate, issuer: x509.Certificate, issues: list,
                          warnings: list, stapled_ocsp: bytes | None = None,
                          now: datetime | None = None, outcome: dict | None = None) -> bool:
    """
    Check whether the leaf certificate is revoked, as described above.

    Args:
        outcome (dict): If given, receives "ocsp_scts": the SCT list of the
            stapled OCSP response, when the response was used and is good.
            Firefox only reads SCTs from a stapled response it consulted.

    Returns:
        bool: False if the certificate is revoked or its stapled response is
        not acceptable.
    """
    now = now or datetime.now(timezone.utc)
    if cert.not_valid_after_utc < now:
        return True
    crl_urls, ocsp_urls = revocation_urls(cert)
    if not crl_urls and not ocsp_urls and stapled_ocsp is None:
        warnings.append(NO_REVOCATION_INFO)

    # 1. CRLite (stand-in: the CRL)
    for crl_url in crl_urls:
        result = _crl_revokes(crl_url, cert, issuer, now)
        if result is True:
            issues.append(CRL_REVOKED)
            return False
        if result is False:
            return True
        warnings.append(f"Failed to check CRL at {crl_url}: {result}")

    # 2. Stapled OCSP response
    if stapled_ocsp is not None:
        status, ocsp_scts = evaluate_ocsp(stapled_ocsp, cert, issuer, now)
        if status == GOOD:
            if outcome is not None and ocsp_scts:
                outcome["ocsp_scts"] = ocsp_scts
            return True
        if status == REVOKED:
            issues.append(STAPLED_OCSP_REVOKED)
            return False
        if status not in TOLERATED_STAPLED:
            issues.append(STAPLED_OCSP_INVALID.format(reason=status))
            return False
        warnings.append(STAPLED_OCSP_IGNORED.format(reason=status))

    # 3. Short-lived certificates
    if cert.not_valid_after_utc - cert.not_valid_before_utc < SHORT_LIFETIME:
        return True

    # 4. CRLite (stand-in: OCSP)
    for ocsp_url in ocsp_urls:
        status = _query_ocsp(ocsp_url, cert, issuer, now)
        if status == REVOKED:
            issues.append(OCSP_REVOKED)
            return False
        if status == GOOD:
            return True
        warnings.append(f"Failed to check OCSP at {ocsp_url}: {status}")
    return True


def check_must_staple(cert: x509.Certificate, stapled_ocsp: bytes | None, issues: list) -> bool:
    """
    A certificate with the TLS Feature extension (OCSP Must-Staple) needs a
    stapled OCSP response; Firefox does not support any other TLS feature.
    """
    features = extension(cert, x509.TLSFeature)
    if features is None:
        return True
    if stapled_ocsp is None or any(feature != TLSFeatureType.status_request for feature in features):
        issues.append(MUST_STAPLE_MISSING)
        return False
    return True


def revocation_urls(cert: x509.Certificate) -> tuple[list, list]:
    """(CRL URLs, OCSP URLs) of a certificate."""
    crl_points = extension(cert, x509.CRLDistributionPoints) or []
    crl_urls = [point.full_name[0].value for point in crl_points if point.full_name]
    aia = extension(cert, x509.AuthorityInformationAccess) or []
    ocsp_urls = [desc.access_location.value for desc in aia
                 if desc.access_method == AuthorityInformationAccessOID.OCSP]
    return crl_urls, ocsp_urls


def _crl_revokes(url: str, cert: x509.Certificate, issuer: x509.Certificate, now: datetime):
    """
    Look the certificate up in a CRL. A listed certificate is revoked. That
    it is not listed only settles the question (as CRLite would) if the CRL
    is current and complete for end-entity certificates (see _crl_coverage).

    Returns:
        True if the CRL lists the certificate, False if a current and
        complete CRL does not, or a string describing why the CRL could not
        be used.
    """
    try:
        crl = _download_crl(url, now)
    except FetchError as e:
        return str(e)
    except ValueError:
        return "invalid CRL"
    if crl.issuer != issuer.subject:
        return "CRL is not issued by the certificate's issuer"
    try:
        verify_signed_data(issuer.public_key(), crl.signature, crl.tbs_certlist_bytes,
                           crl.signature_hash_algorithm, crl.signature_algorithm_parameters)
    except (InvalidSignature, UnsupportedSignature, UnsupportedAlgorithm, ValueError):
        return "CRL signature could not be verified"
    if _is_indirect(crl):
        return "indirect CRLs are not supported"
    if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
        return True
    return _crl_coverage(crl, now) or False


def clear_caches() -> None:
    """Forget the cached CRLs and OCSP responses."""
    _crl_cache.clear()
    _ocsp_cache.clear()


def _cache_until(next_update: datetime | None, now: datetime) -> datetime | None:
    """When a downloaded CRL or OCSP response stops being reused, or None if it is not cached."""
    if next_update is None or CACHE_MAX_AGE <= timedelta(0):
        return None
    return min(next_update, now + CACHE_MAX_AGE)


def _download_crl(url: str, now: datetime) -> x509.CertificateRevocationList:
    """
    Download and parse a CRL, or reuse the copy downloaded earlier (see
    CACHE_MAX_AGE). Its signature is checked by the caller on every use.

    Raises:
        FetchError: If the download fails.
        ValueError: If it is not a CRL.
    """
    crl = _crl_cache.get(url, now)
    if crl is None:
        data = fetch(url)
        crl = x509.load_der_x509_crl(data)
        expires = _cache_until(crl.next_update_utc, now)
        if expires is not None:
            _crl_cache.put(url, crl, len(data), expires, now)
    return crl


def _download_ocsp(url: str, request: bytes, now: datetime) -> bytes:
    """
    Send an OCSP request, or reuse the response received earlier for the same
    request (see CACHE_MAX_AGE). Only successful responses are cached, until
    the earliest next update of their certificate statuses.

    Raises:
        FetchError: If the request fails.
    """
    key = (url, request)
    content = _ocsp_cache.get(key, now)
    if content is None:
        content = fetch(url, data=request, content_type="application/ocsp-request")
        try:
            response = load_der_ocsp_response(content)
            if response.response_status == OCSPResponseStatus.SUCCESSFUL:
                updates = [single.next_update_utc for single in response.responses]
                if updates and None not in updates:
                    expires = _cache_until(min(updates), now)
                    if expires is not None:
                        _ocsp_cache.put(key, content, len(content), expires, now)
        except ValueError:
            pass
    return content


def _is_indirect(crl: x509.CertificateRevocationList) -> bool:
    """Whether the CRL lists certificates of other issuers (their serials could clash)."""
    point = extension(crl, x509.IssuingDistributionPoint)
    return point is not None and point.indirect_crl


def _crl_coverage(crl: x509.CertificateRevocationList, now: datetime) -> str | None:
    """
    Why a CRL that does not list the certificate cannot prove it is not
    revoked, or None if it can: it has expired (its next update is past), it
    only covers CA or attribute certificates or some revocation reasons, or
    it is a delta CRL (only the changes since a full CRL).
    """
    next_update = crl.next_update_utc
    if next_update is not None and next_update < now:
        return "CRL has expired"
    point = extension(crl, x509.IssuingDistributionPoint)
    if point is not None and (point.only_contains_ca_certs or point.only_contains_attribute_certs):
        return "CRL does not cover end-entity certificates"
    if point is not None and point.only_some_reasons:
        return "CRL only covers some revocation reasons"
    if extension(crl, x509.DeltaCRLIndicator) is not None:
        return "delta CRLs are not supported"
    return None


def _query_ocsp(url: str, cert: x509.Certificate, issuer: x509.Certificate, now: datetime) -> str:
    """
    Ask an OCSP responder about the certificate. The request identifies the
    certificate with SHA-1, as Firefox does (many responders reject SHA-256).
    """
    request = OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1()).build()
    try:
        content = _download_ocsp(url, request.public_bytes(serialization.Encoding.DER), now)
    except FetchError as e:
        return str(e)
    return evaluate_ocsp(content, cert, issuer, now)[0]


def evaluate_ocsp(der: bytes, cert: x509.Certificate, issuer: x509.Certificate,
                  now: datetime) -> tuple[str, bytes | None]:
    """
    Verify an OCSP response about `cert` the way mozilla::pkix does.

    Returns:
        tuple: (result, SCT list): result is GOOD, REVOKED or a description
        of the problem; the SCT list (encoded, from the response's SCT
        extension) is only returned for a good response.
    """
    try:
        response = load_der_ocsp_response(der)
    except ValueError:
        return MALFORMED, None
    if response.response_status != OCSPResponseStatus.SUCCESSFUL:
        return f"responder answered {response.response_status.name}", None
    signature = _ocsp_signature_status(response, issuer, now)
    if signature is not None:
        return signature, None

    status, expired, matched = None, False, False
    for single in response.responses:
        if not _matches_cert_id(single, cert, issuer):
            continue
        matched = True
        this_update, next_update = single.this_update_utc, single.next_update_utc
        if this_update > now + OCSP_SLOP:
            return FUTURE, None
        if next_update is not None:
            if next_update < this_update:
                return MALFORMED, None
            valid_through = min(next_update, this_update + OCSP_MAX_LIFETIME)
        else:
            valid_through = this_update + OCSP_NO_NEXT_UPDATE_LIFETIME
        expired = now > valid_through + OCSP_SLOP
        # revoked overrides good, which overrides unknown
        if single.certificate_status == OCSPCertStatus.REVOKED:
            status = REVOKED
        elif single.certificate_status == OCSPCertStatus.GOOD and status != REVOKED:
            status = GOOD
        elif status is None:
            status = UNKNOWN
    if not matched:
        return NOT_FOR_CERTIFICATE, None
    if status == GOOD:
        return (OLD, None) if expired else (GOOD, _ocsp_scts(response))
    return status, None


def _matches_cert_id(single, cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Whether a single response is about this certificate (serial, issuer name and key hashes)."""
    if single.serial_number != cert.serial_number:
        return False
    hash_class = _HASHES.get(single.hash_algorithm.name)
    if hash_class is None:
        return False
    name_hash = hashes.Hash(hash_class())
    name_hash.update(cert.issuer.public_bytes())
    key_hash = hashes.Hash(hash_class())
    key_hash.update(_public_key_bits(issuer))
    return single.issuer_name_hash == name_hash.finalize() and single.issuer_key_hash == key_hash.finalize()


def _public_key_bits(cert: x509.Certificate) -> bytes:
    """The subjectPublicKey BIT STRING contents of a certificate (hashed in OCSP CertIDs)."""
    spki = cert.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    position = _skip_header(spki, 0)              # SubjectPublicKeyInfo SEQUENCE
    position = _skip_element(spki, position)      # AlgorithmIdentifier
    bits_start = _skip_header(spki, position)     # BIT STRING
    return spki[bits_start + 1:]                  # without the unused-bits byte


def _skip_header(der: bytes, position: int) -> int:
    """Position of the contents of the DER element at `position`."""
    length = der[position + 1]
    if length < 0x80:
        return position + 2
    return position + 2 + (length & 0x7F)


def _element_length(der: bytes, position: int) -> int:
    length = der[position + 1]
    if length < 0x80:
        return length
    count = length & 0x7F
    return int.from_bytes(der[position + 2:position + 2 + count], "big")


def _skip_element(der: bytes, position: int) -> int:
    """Position of the element following the DER element at `position`."""
    return _skip_header(der, position) + _element_length(der, position)


def unwrap_octet_string(der: bytes) -> bytes:
    """The contents of a DER OCTET STRING."""
    return der[_skip_header(der, 0):_skip_element(der, 0)]


def _ocsp_scts(response) -> bytes | None:
    """The SCT list of a single-certificate OCSP response, if it has one."""
    try:
        sct_extension = response.single_extensions.get_extension_for_oid(SCT_OCSP_EXTENSION)
        return unwrap_octet_string(sct_extension.value.public_bytes())
    except (x509.ExtensionNotFound, *EXTENSION_ERRORS, AttributeError, IndexError):
        return None


def _ocsp_signature_status(response, issuer: x509.Certificate, now: datetime) -> str | None:
    """
    None if the response is signed by the issuer, or by a responder
    certificate the issuer authorised (an end-entity certificate issued by
    it, valid now, with the OCSP signing purpose); otherwise the problem.
    """
    def is_responder(cert):
        if response.responder_name is not None:
            return response.responder_name == cert.subject
        try:
            key_id = x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest
        except (ValueError, TypeError, UnsupportedAlgorithm):
            return False
        return response.responder_key_hash == key_id

    def authorised(cert):
        """mozilla::pkix's CheckOCSPResponseSignerCert."""
        return (not rules.extension_problems(cert)
                and is_signed_by(cert, issuer)
                and ExtendedKeyUsageOID.OCSP_SIGNING in (extension(cert, x509.ExtendedKeyUsage) or [])
                and rules.LEAF_IS_CA not in rules.leaf_problems(cert)  # an end-entity certificate
                and rules.is_within_validity(cert, now)
                and not rules.key_problems(cert)
                and not rules.signature_problems(cert)
                and not TrustStore.mozilla().onecrl.revokes(cert))

    if is_responder(issuer):
        signer = issuer
    else:
        signer = next((c for c in response.certificates if is_responder(c) and authorised(c)), None)
        if signer is None:
            return INVALID_SIGNING_CERT
    parameters = None
    try:
        if response.signature_algorithm_oid == SignatureAlgorithmOID.RSASSA_PSS:
            parameters = padding.PSS(mgf=padding.MGF1(response.signature_hash_algorithm),
                                     salt_length=padding.PSS.AUTO)
        verify_signed_data(signer.public_key(), response.signature, response.tbs_response_bytes,
                           response.signature_hash_algorithm, parameters)
        return None
    except (InvalidSignature, UnsupportedSignature, UnsupportedAlgorithm, ValueError):
        return BAD_SIGNATURE
