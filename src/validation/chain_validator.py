"""
Builds the certificate chain of a domain and validates every certificate in it.
"""

import socket
from concurrent.futures import Future
from datetime import datetime, timezone

from src.chain.name_constraints import path_violations
from src.chain.path_builder import ORIGIN_AIA, PathBuilder
from src.chain.signatures import is_self_signed
from src.fetch.tls import Handshake
from src.trust.store import TrustStore, load_pem_certificates
from src.validation import transparency
from src.validation.certificate_fields import CertificateFields
from src.validation.certificate_validator import INTERMEDIATE, LEAF, ROOT, CertificateValidator

# Analysis notes
EXTRA_CERTIFICATES = "Extra certificates were provided."
FETCHED_FROM_AIA = "Missing certificates had to be fetched from AIA."
UNTRUSTED_CHAIN = "Chain does not lead to a root in the Mozilla trust store."
FIREFOX_REJECTS = "Firefox would not accept this chain."
PIN_MISMATCH = "Chain contains none of the keys Firefox pins for this host."
CT_NOT_CHECKED = "Certificate Transparency was not checked: the CT log list has expired or is missing."
# Certificate issues and warnings added at chain level
UNTRUSTED_ROOT = "Root CA is not in the Mozilla trust store"
MISSING_FETCHED = "Certificate was missing and fetched from AIA."
ONECRL_REVOKED = "Certificate is revoked (OneCRL)"
NAME_CONSTRAINTS = "Name not permitted by an issuer's name constraints"
DISTRUSTED_ROOT = "Root CA is distrusted for certificates issued after {date:%Y-%m-%d}"


class ChainValidator:
    """Build and validate the certificate chain of a domain."""

    @staticmethod
    def build_chain(pem_certs: list, hostname: str | None = None) -> tuple[list, list, bool, bool]:
        """
        Build the chain the way Firefox does (see src/chain/path_builder.py).

        Args:
            pem_certs (list): PEM certificates as sent by the server, leaf first.
            hostname (str): The server's host name, for Firefox's key pins.

        Returns:
            tuple: (chain, extra, trusted, strict)
                chain: dicts with "id", "origin" and "cert" (x509.Certificate),
                    leaf first.
                extra: server certificates that are duplicates or unrelated
                    to the chain.
                trusted: True if the chain ends at a root of the Mozilla store.
                strict: True if Firefox would build this chain too.
        """
        certs = load_pem_certificates("\n".join(pem_certs).encode())
        if not certs:
            return [], [], False, False
        result = PathBuilder.mozilla().build(certs, hostname=hostname)

        chain = []
        last = len(result.path) - 1
        for pos, (cert, origin) in enumerate(result.path):
            if pos == 0:
                cert_id = LEAF
            elif pos == last and (result.trusted or is_self_signed(cert)):
                cert_id = ROOT
            else:
                cert_id = INTERMEDIATE
            chain.append({"id": cert_id, "origin": origin, "cert": cert})
        return chain, result.extra, result.trusted, result.strict

    @staticmethod
    def validate_chain(domain: str, chain: list, extra: list, trusted: bool,
                       show_cert: bool, original_domain: str | None = None,
                       strict: bool = True, handshake: Handshake | None = None,
                       dnssec: Future | None = None) -> dict:
        """
        Validate every certificate of a chain built by build_chain.

        Args:
            domain (str): The domain the chain was retrieved from.
            chain (list): The chain returned by build_chain.
            extra (list): The extra certificates returned by build_chain.
            trusted (bool): Whether the chain ends at a trusted root.
            strict (bool): Whether Firefox would build this chain too. If not
                (e.g. an expired intermediate, a SHA-1 signature or an issuer
                downloaded through AIA), the chain is invalid.
            show_cert (bool): Include the decoded certificate fields.
            original_domain (str): The requested domain, if it redirected
                to `domain`.
            handshake (Handshake): What the server sent besides its
                certificates: stapled OCSP response and SCTs.
            dnssec (Future): The DNSSEC check of `domain`
                (certificate_validator.check_dnssec), started in parallel by
                the caller; if None, it is run during validation.

        Returns:
            dict: The analysis response.
        """
        response = {
            "domain": domain,
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "ip-address": _ip_address(domain),
            "redirect": original_domain is not None,
            "original": original_domain if original_domain is not None else domain,
            "status": "valid",
            "analysis": [],
            "chain": []
        }
        if extra:
            response["analysis"].append(EXTRA_CERTIFICATES)
        if any(entry["origin"] == ORIGIN_AIA for entry in chain):
            response["analysis"].append(FETCHED_FROM_AIA)
        if not trusted:
            response["analysis"].append(UNTRUSTED_CHAIN)
            response["status"] = "invalid"
        elif not strict:
            response["analysis"].append(FIREFOX_REJECTS)
            response["status"] = "invalid"

        handshake = handshake or Handshake()
        mozilla = PathBuilder.mozilla(aia_fetcher=None)
        certs = [entry["cert"] for entry in chain]
        if trusted and not mozilla.has_valid_pins(domain, certs):
            response["analysis"].append(PIN_MISMATCH)
            response["status"] = "invalid"

        constrained = set(path_violations(certs))
        revocation_outcome = {}
        for pos, entry in enumerate(chain):
            cert_data = ChainValidator._validate_entry(domain, chain, pos, trusted, pos in constrained,
                                                       mozilla, handshake, revocation_outcome,
                                                       dnssec if pos == 0 else None)
            if pos == 0 and trusted:
                ChainValidator._check_transparency(chain, handshake, mozilla, cert_data, response,
                                                   revocation_outcome.get("ocsp_scts"))
            if cert_data["status"] == "invalid":
                response["status"] = "invalid"
            if not show_cert:
                cert_data.pop("certificate")
            response["chain"].append(cert_data)
        return response

    @staticmethod
    def _check_transparency(chain: list, handshake: Handshake, mozilla: PathBuilder,
                            leaf_data: dict, response: dict, ocsp_scts: bytes | None) -> None:
        """
        Firefox's Certificate Transparency requirement, for a chain to a
        Mozilla root. Like Firefox, which only checks CT once the chain is
        otherwise acceptable, it is skipped for a leaf outside its validity
        period (whose logs may no longer be in Firefox's list).

        ocsp_scts are the SCTs of the stapled OCSP response, only if the
        revocation check used that response (Firefox does not read it when
        CRLite settles the question).
        """
        leaf = chain[0]["cert"]
        now = datetime.now(timezone.utc)
        if not leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc:
            return
        issuer = chain[1]["cert"] if len(chain) > 1 else None
        result = transparency.check_transparency(
            leaf, issuer, TrustStore.mozilla().ct_logs, handshake.tls_scts, ocsp_scts, now,
            distrust_after=mozilla.distrust_date(chain[-1]["cert"]))
        if result is None:
            response["analysis"].append(CT_NOT_CHECKED)
        elif not result.compliant:
            leaf_data["issues"].append(transparency.CT_NOT_COMPLIANT)
            leaf_data["warnings"].append(result.details())
            leaf_data["status"] = "invalid"

    @staticmethod
    def _validate_entry(domain: str, chain: list, pos: int, trusted: bool,
                        breaks_name_constraints: bool, mozilla: PathBuilder,
                        handshake: Handshake, revocation_outcome: dict,
                        dnssec: Future | None = None) -> dict:
        """Validate the certificate at `pos` and build its response entry."""
        entry = chain[pos]
        cert = entry["cert"]
        if entry["id"] == ROOT:
            issuer = cert
        elif pos + 1 < len(chain):
            issuer = chain[pos + 1]["cert"]
        else:
            issuer = None
        issuer_is_root = pos + 1 < len(chain) and chain[pos + 1]["id"] == ROOT

        valid, issues, warnings = CertificateValidator.validate(
            domain, cert, issuer, entry["id"], position=pos, issuer_is_root=issuer_is_root,
            stapled_ocsp=handshake.stapled_ocsp, revocation_outcome=revocation_outcome,
            dnssec_warnings=dnssec.result() if dnssec is not None else None)
        if entry["id"] == ROOT and not trusted:
            issues.append(UNTRUSTED_ROOT)
            valid = False
        if mozilla.is_revoked(cert):
            issues.append(ONECRL_REVOKED)
            valid = False
        if breaks_name_constraints:
            issues.append(NAME_CONSTRAINTS)
            valid = False
        if entry["id"] == ROOT and mozilla.distrusts(cert, chain[0]["cert"]):
            issues.append(DISTRUSTED_ROOT.format(date=mozilla.distrust_date(cert)))
            valid = False
        if entry["origin"] == ORIGIN_AIA:
            warnings.append(MISSING_FETCHED)

        return {
            "id": entry["id"],
            "origin": entry["origin"],
            "status": "valid" if valid else "invalid",
            "issues": issues,
            "warnings": warnings,
            "certificate": CertificateFields.decode(cert),
        }


def _ip_address(domain: str) -> str | None:
    """The domain's IPv4 address, or its IPv6 address if it has none."""
    try:
        infos = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return None
    addresses = [info[4][0] for info in infos]
    ipv4 = [a for a in addresses if ":" not in a]
    return (ipv4 or addresses or [None])[0]
