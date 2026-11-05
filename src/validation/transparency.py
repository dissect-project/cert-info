"""
Certificate Transparency (CT), as Firefox enforces it
(security/ct: MultiLogCTVerifier.cpp, CTPolicyEnforcer.cpp).

A leaf certificate that chains to a Mozilla root must come with Signed
Certificate Timestamps (SCTs): promises by CT logs that the certificate was
published. SCTs can be embedded in the certificate, sent in the TLS
handshake, or included in the stapled OCSP response. An SCT counts if it is
from a log Firefox knows (src/trust/data/firefox-ct-logs.json), its signature
verifies, it is not dated in the future, and it is not dated after the
root's distrust date. Then the policy:

- Two valid SCTs delivered in the TLS handshake or OCSP response, from two
  different logs of two different operators, are enough. Only logs that are
  still admissible count.
- Otherwise, the embedded SCTs must include at least one from an
  admissible log, and come from 2 different logs (3 if the certificate is
  valid for more than 180 days) and 2 different operators. SCTs from a
  retired log count if the log was retired after the certificate was issued.
- SCTs from tiled (static-ct-api) logs must carry the certificate's index in
  the log.

Firefox stops enforcing CT when its log list has expired.
"""

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtensionOID

from src.chain.certificate_rules import EXTENSION_ERRORS
from src.trust.store import CTLog, CTLogList
from src.validation.revocation import unwrap_octet_string

# Issue
CT_NOT_COMPLIANT = "Certificate does not meet Firefox's Certificate Transparency requirements"
# Warning
CT_DETAILS = ("Certificate Transparency: {valid} valid SCTs (embedded: {embedded}, TLS: {tls}, "
              "OCSP: {ocsp}); {unknown} from unknown logs, {invalid} invalid")

EMBEDDED, TLS_EXTENSION, OCSP_RESPONSE = "embedded", "TLS", "OCSP"
ONE_HUNDRED_AND_EIGHTY_DAYS = timedelta(days=180)

_X509_ENTRY, _PRECERT_ENTRY = 0, 1
_SHA256 = 4
_SIG_RSA, _SIG_ECDSA = 1, 3
_LEAF_INDEX_EXTENSION = 0


@dataclass
class SCT:
    log_id: bytes
    timestamp: int          # milliseconds since the epoch
    extensions: bytes
    hash_algorithm: int
    signature_algorithm: int
    signature: bytes
    leaf_index: int | None = None


@dataclass
class VerifiedSCT:
    sct: SCT
    log: CTLog
    origin: str


@dataclass
class CTResult:
    compliant: bool
    verified: list
    unknown_log: int = 0
    invalid: int = 0

    def details(self) -> str:
        count = lambda origin: sum(1 for v in self.verified if v.origin == origin)  # noqa: E731
        return CT_DETAILS.format(valid=len(self.verified), embedded=count(EMBEDDED),
                                 tls=count(TLS_EXTENSION), ocsp=count(OCSP_RESPONSE),
                                 unknown=self.unknown_log, invalid=self.invalid)


class _Reader:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, length: int) -> bytes:
        if self.pos + length > len(self.data):
            raise ValueError("truncated")
        chunk = self.data[self.pos:self.pos + length]
        self.pos += length
        return chunk

    def number(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")

    def vector(self, length_size: int) -> bytes:
        return self.take(self.number(length_size))

    def at_end(self) -> bool:
        return self.pos >= len(self.data)


def decode_sct_list(data: bytes | None) -> tuple[list, int]:
    """(SCTs, number of SCTs that could not be decoded) of a SignedCertificateTimestampList."""
    if not data:
        return [], 0
    try:
        items = _Reader(_Reader(data).vector(2))
    except ValueError:
        return [], 1
    scts, errors = [], 0
    while not items.at_end():
        try:
            item = items.vector(2)
        except ValueError:
            return scts, errors + 1
        try:
            scts.append(_decode_sct(item))
        except ValueError:
            errors += 1
    return scts, errors


def _decode_sct(data: bytes) -> SCT:
    reader = _Reader(data)
    if reader.number(1) != 0:
        raise ValueError("unsupported SCT version")
    sct = SCT(log_id=reader.take(32), timestamp=reader.number(8), extensions=reader.vector(2),
              hash_algorithm=reader.number(1), signature_algorithm=reader.number(1),
              signature=reader.vector(2))
    if not reader.at_end():
        raise ValueError("trailing data")
    extensions = _Reader(sct.extensions)
    while not extensions.at_end():
        ext_type, ext_data = extensions.number(1), extensions.vector(2)
        if ext_type == _LEAF_INDEX_EXTENSION:
            if sct.leaf_index is not None or len(ext_data) != 5:
                raise ValueError("invalid leaf_index extension")
            sct.leaf_index = int.from_bytes(ext_data, "big")
    return sct


def _signed_data(sct: SCT, entry_type: int, entry: bytes) -> bytes:
    """The data an SCT signature covers (RFC 6962, section 3.2)."""
    return (b"\x00\x00" + sct.timestamp.to_bytes(8, "big") + entry_type.to_bytes(2, "big")
            + entry + len(sct.extensions).to_bytes(2, "big") + sct.extensions)


def _verify(log: CTLog, sct: SCT, data: bytes) -> bool | None:
    """True if valid, False if the signature is wrong, None if the parameters do not match the log."""
    key = serialization.load_der_public_key(log.key)
    if sct.hash_algorithm != _SHA256:
        return None
    try:
        if isinstance(key, ec.EllipticCurvePublicKey) and sct.signature_algorithm == _SIG_ECDSA:
            key.verify(sct.signature, data, ec.ECDSA(hashes.SHA256()))
        elif isinstance(key, rsa.RSAPublicKey) and sct.signature_algorithm == _SIG_RSA:
            key.verify(sct.signature, data, padding.PKCS1v15(), hashes.SHA256())
        else:
            return None
        return True
    except (InvalidSignature, ValueError):
        return False


def _embedded_sct_list(leaf: x509.Certificate) -> bytes | None:
    try:
        ext = leaf.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        return unwrap_octet_string(ext.value.public_bytes())
    except (x509.ExtensionNotFound, *EXTENSION_ERRORS, IndexError):
        return None


def verify_scts(leaf: x509.Certificate, issuer: x509.Certificate, logs: CTLogList,
                tls_scts: bytes | None, ocsp_scts: bytes | None, now: datetime,
                distrust_after: datetime | None = None) -> CTResult:
    """Verify every SCT of the leaf against Firefox's logs."""
    result = CTResult(compliant=False, verified=[])
    issuer_spki = issuer.public_key().public_bytes(serialization.Encoding.DER,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo)
    leaf_der = leaf.public_bytes(serialization.Encoding.DER)
    x509_entry = len(leaf_der).to_bytes(3, "big") + leaf_der
    sources = [(TLS_EXTENSION, tls_scts, _X509_ENTRY, x509_entry),
               (OCSP_RESPONSE, ocsp_scts, _X509_ENTRY, x509_entry)]
    embedded = _embedded_sct_list(leaf)
    if embedded:
        tbs = leaf.tbs_precertificate_bytes
        precert_entry = hashlib.sha256(issuer_spki).digest() + len(tbs).to_bytes(3, "big") + tbs
        sources.insert(0, (EMBEDDED, embedded, _PRECERT_ENTRY, precert_entry))

    for origin, encoded, entry_type, entry in sources:
        scts, errors = decode_sct_list(encoded)
        result.invalid += errors
        for sct in scts:
            log = logs.logs.get(sct.log_id)
            if log is None:
                result.unknown_log += 1
                continue
            if not _verify(log, sct, _signed_data(sct, entry_type, entry)):
                result.invalid += 1
                continue
            sct_time = datetime.fromtimestamp(sct.timestamp // 1000, timezone.utc)
            if sct_time > now or (distrust_after is not None and sct_time > distrust_after):
                result.invalid += 1
                continue
            result.verified.append(VerifiedSCT(sct, log, origin))
    return result


def _usable(verified: VerifiedSCT) -> bool:
    """SCTs of tiled logs must carry the leaf index."""
    return not (verified.log.tiled and verified.sct.leaf_index is None)


def _qualified(verified: VerifiedSCT, issuance_ms: int) -> bool:
    """Whether the log was admissible, or retired after the certificate was issued and the SCT made."""
    if verified.log.admissible:
        return True
    retired_ms = int(verified.log.timestamp.timestamp() * 1000)
    return issuance_ms < retired_ms and verified.sct.timestamp < retired_ms


def is_compliant(verified: list, cert_lifetime: timedelta) -> bool:
    """Firefox's CT policy (CTPolicyEnforcer.cpp)."""
    delivered = [v for v in verified if v.origin != EMBEDDED and v.log.admissible and _usable(v)]
    if len(delivered) >= 2 and len({v.sct.log_id for v in delivered}) >= 2 \
            and len({v.log.operator_id for v in delivered}) >= 2:
        return True

    admissible_times = [v.sct.timestamp for v in verified if v.log.admissible]
    issuance_ms = min(admissible_times) if admissible_times else 2 ** 64 - 1
    required = 3 if cert_lifetime > ONE_HUNDRED_AND_EIGHTY_DAYS else 2
    admissible_count, qualified_count, log_ids, operators = 0, 0, set(), set()
    for v in verified:
        if v.origin != EMBEDDED or not _usable(v):
            continue
        qualified = _qualified(v, issuance_ms)
        if not v.log.admissible and not qualified:
            continue
        if v.log.admissible:
            admissible_count += 1
        if qualified:
            qualified_count += 1
            log_ids.add(v.sct.log_id)
        operators.add(v.log.operator_id)
    return admissible_count >= 1 and qualified_count >= required \
        and len(log_ids) >= required and len(operators) >= 2


def check_transparency(leaf: x509.Certificate, issuer: x509.Certificate | None, logs: CTLogList,
                       tls_scts: bytes | None = None, ocsp_scts: bytes | None = None,
                       now: datetime | None = None,
                       distrust_after: datetime | None = None) -> CTResult | None:
    """
    Check the leaf of a chain that ends at a Mozilla root. Returns None if
    Firefox would not enforce CT (no log list, or the list has expired).
    """
    now = now or datetime.now(timezone.utc)
    if logs.expiration is None or now > logs.expiration:
        return None
    if issuer is None:
        return CTResult(compliant=False, verified=[])
    result = verify_scts(leaf, issuer, logs, tls_scts, ocsp_scts, now, distrust_after)
    lifetime = leaf.not_valid_after_utc - leaf.not_valid_before_utc
    result.compliant = is_compliant(result.verified, lifetime)
    return result
