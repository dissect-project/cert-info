"""
Firefox-style certificate path building.

This module builds the chain the same way Firefox (mozilla::pkix) does, so the
chain cert-info reports is the one a Firefox user sees:

- The certificates sent by the server are an unordered pool. Their order and
  any extra certificates are ignored.
- An issuer is a certificate whose subject is exactly the child's issuer name
  and whose key verifies the child's signature. Names are compared on their
  encoded form; key identifiers are not used, as in mozilla::pkix.
- Candidates are tried in this order: Mozilla roots, certificates sent by the
  server, then Firefox's preloaded intermediates (CCADB, distributed through
  Remote Settings).
- Building stops at the first trusted root. A cross-signed copy of a trusted
  root is therefore never used when the root itself is in the store.
- Every candidate issuer, the trust anchor included, must pass Firefox's
  checks (src/chain/certificate_rules.py): validity period, Basic
  Constraints, Key Usage, Extended Key Usage, path length, supported
  extensions and key; intermediates must also be signed with a supported
  algorithm (not SHA-1). Otherwise the next candidate is tried
  (backtracking). A root's own self-signature is never checked.
- Revoked certificates (OneCRL, Mozilla's list of revoked CA certificates)
  are never used; certificates that break a CA's name constraints are not
  used below it; a certificate must repeat its issuer's TLS Feature
  extension (OCSP Must-Staple). On reaching a trust anchor, the chain is
  rejected if the leaf was issued after the root's distrust date, or if the
  host has static key pins and the chain contains none of the pinned keys.
  Firefox then tries other paths.
- Problems of the leaf itself (expiry, OneCRL, unsupported key, ...) do not
  change the path; Firefox reports them after building it, and so does the
  certificate validator.
- RSA keys: Firefox first requires 2048 bits in every certificate, then
  retries with 1024 bits, so a path with only 2048-bit keys is preferred.
- Extended Validation first: for each EV policy OID in the leaf, in order,
  Firefox tries to build a chain in which every certificate asserts that
  policy (intermediates may assert anyPolicy) and that ends at a root its EV
  list registers for the policy. Other roots are not trusted in that attempt,
  so an EV chain can go through a cross-signed copy of a newer root to an
  older one. EV chains need 2048-bit RSA keys. Only if no EV chain exists is
  the ordinary chain built.

Firefox does not fetch missing issuers through AIA. When no trusted path
exists, an optional AIA fetcher is used to complete the chain as far as
possible, so the analysis can still report on it.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from typing import Callable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from src.chain import certificate_rules as rules
from src.chain.aia import fetch_issuer_from_aia
from src.chain.name_constraints import permits as name_constraints_permit
from src.chain.pinning import chain_has_valid_pins
from src.chain.signatures import is_self_signed, is_signed_by
from src.trust.store import OneCRL, StaticPins, TrustStore

# CA/Browser Forum EV policy: every EV root is trusted for it
CABF_EV_POLICY = "2.23.140.1.1"
ANY_POLICY = "2.5.29.32.0"

# Values used in the "origin" field of each chain entry
ORIGIN_SERVER = "Server"
ORIGIN_ROOTS = "Mozilla CA Bundle"
ORIGIN_PRELOAD = "Mozilla Intermediate Preload"
ORIGIN_AIA = "AIA"

# mozilla::pkix allows at most 6 sub-CAs: end-entity + 6 + trust anchor
MAX_PATH_LENGTH = 8
# Maximum number of issuers fetched through AIA for one chain
MAX_AIA_FETCHES = 4
# Maximum number of candidate issuers examined per search, counted as in
# mozilla::pkix (buildForwardCallBudget): candidates that pass the loop,
# name constraint and TLS feature checks. When it runs out, the search fails.
SEARCH_BUDGET = 200_000


def _policies(cert: x509.Certificate) -> list | None:
    """Policy OIDs of the Certificate Policies extension, or None without it."""
    try:
        policies = cert.extensions.get_extension_for_class(x509.CertificatePolicies).value
    except x509.ExtensionNotFound:
        return None
    except rules.EXTENSION_ERRORS:
        return []
    return [policy.policy_identifier.dotted_string for policy in policies]


def _asserts_policy(cert: x509.Certificate, policy: str, is_ca: bool) -> bool:
    """
    mozilla::pkix's policy check for EV: the certificate asserts the policy
    (or anyPolicy, for CA certificates) and has no inhibitAnyPolicy extension.
    """
    try:
        cert.extensions.get_extension_for_class(x509.InhibitAnyPolicy)
        return False
    except x509.ExtensionNotFound:
        pass
    except rules.EXTENSION_ERRORS:
        return False
    policies = _policies(cert) or []
    return policy in policies or (is_ca and ANY_POLICY in policies)


@lru_cache(maxsize=8192)
def _identity(cert: x509.Certificate) -> tuple:
    """
    Subject and public key of a certificate. mozilla::pkix rejects paths in
    which the same subject and key appear twice.
    """
    try:
        key = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception:
        # Unsupported key type: fall back to the certificate fingerprint
        key = cert.fingerprint(hashes.SHA256())
    return cert.subject.public_bytes(), key


def _usable_issuer(issuer: x509.Certificate, now: datetime, sub_cas_below: int,
                  is_trust_anchor: bool, min_rsa_bits: int) -> bool:
    """
    The checks mozilla::pkix applies to a CA certificate before using it,
    trust anchors included (see src/chain/certificate_rules.py). Only
    intermediates have their own signature algorithm checked.

    Args:
        issuer (x509.Certificate): The candidate CA certificate.
        now (datetime): The verification time.
        sub_cas_below (int): Number of intermediates between it and the leaf.
        is_trust_anchor (bool): Whether it is a root of the trust store.
        min_rsa_bits (int): Minimum RSA key size of this attempt.

    Returns:
        bool: True if the certificate can be used in the path.
    """
    if rules.extension_problems(issuer) or not rules.is_within_validity(issuer, now):
        return False
    if rules.issuer_problems(issuer, sub_cas_below, is_trust_anchor):
        return False
    if rules.key_problems(issuer, min_rsa_bits):
        return False
    return is_trust_anchor or not rules.signature_problems(issuer)


@lru_cache(maxsize=65536)
def _signed_by(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    """is_signed_by, remembered: the same pairs are tried in every search attempt."""
    return is_signed_by(child, issuer)


def _index_by_subject(certs: list) -> dict:
    """Index certificates by their encoded subject name."""
    index = {}
    for cert in certs:
        index.setdefault(cert.subject.public_bytes(), []).append(cert)
    return index


@dataclass
class PathResult:
    """
    Result of building a path.

    Attributes:
        path: (certificate, origin) tuples from the leaf to the last
            certificate found.
        trusted: True if the path ends at a root in the Mozilla store.
        strict: True if Firefox would build this path too: it passed all of
            Firefox's checks and needed no AIA download.
        ev_policy: The EV policy the path was built for, or None for an
            ordinary chain.
        extra: Certificates sent by the server that are duplicates or not
            related to the chain.
    """
    path: list
    trusted: bool
    strict: bool = False
    extra: list = field(default_factory=list)
    ev_policy: str | None = None


class PathBuilder:
    """
    Build certificate paths the way Firefox does.

    Args:
        roots (list): Trust anchors (x509.Certificate).
        intermediates (list): Preloaded intermediates (x509.Certificate).
        aia_fetcher (callable): Optional function that takes a certificate and
            returns its issuer or None. Only used when no trusted path exists.
        ev_roots (dict): Firefox's EV roots, SHA-256 fingerprint (hex) -> set
            of policy OIDs (see load_ev_roots). None disables EV.
        distrust (dict): Roots' distrust dates, SHA-256 fingerprint (hex) ->
            datetime (see load_distrust).
        onecrl (OneCRL): Revoked CA certificates.
        pins (StaticPins): Firefox's static key pins.
    """

    def __init__(self, roots: list, intermediates: list,
                 aia_fetcher: Optional[Callable] = None, ev_roots: dict | None = None,
                 distrust: dict | None = None, onecrl: OneCRL | None = None,
                 pins: StaticPins | None = None):
        self._roots = _index_by_subject(roots)
        self._root_set = set(roots)
        self._preloaded = _index_by_subject(intermediates)
        self._aia_fetcher = aia_fetcher
        self._ev_roots = ev_roots or {}
        self._ev_policies = {CABF_EV_POLICY}.union(*self._ev_roots.values()) if self._ev_roots else set()
        self._distrust = distrust or {}
        self._onecrl = onecrl or OneCRL()
        self._pins = pins or StaticPins()

    @classmethod
    def mozilla(cls, aia_fetcher: Optional[Callable] = fetch_issuer_from_aia) -> "PathBuilder":
        """Builder using the bundled Mozilla trust data (see src/trust/store.py)."""
        store = TrustStore.mozilla()
        return cls(store.roots, store.intermediates, aia_fetcher,
                   store.ev_roots, store.distrust, store.onecrl, store.pins)

    def is_revoked(self, cert: x509.Certificate) -> bool:
        """Whether OneCRL lists the certificate."""
        return self._onecrl.revokes(cert)

    def distrust_date(self, root: x509.Certificate) -> datetime | None:
        """The root's distrust date for websites, if it has one."""
        return self._distrust.get(root.fingerprint(hashes.SHA256()).hex())

    def distrusts(self, root: x509.Certificate, leaf: x509.Certificate) -> bool:
        """Whether the root no longer vouches for the leaf (issued after its distrust date)."""
        date = self.distrust_date(root)
        return date is not None and leaf.not_valid_before_utc > date

    def has_valid_pins(self, hostname: str | None, certs: list, now: Optional[datetime] = None) -> bool:
        """Whether a chain to a Mozilla root satisfies the host's static key pins."""
        return chain_has_valid_pins(self._pins, hostname, certs, now or datetime.now(timezone.utc))

    def build(self, server_certs: list, now: Optional[datetime] = None,
              hostname: str | None = None) -> PathResult:
        """
        Build the path for the certificates sent by a server.

        Args:
            server_certs (list): Certificates as sent by the server (x509.Certificate),
                leaf first. The order of the others does not matter.
            now (datetime): Verification time (default: current time).
            hostname (str): The server's host name, for Firefox's key pins.

        Returns:
            PathResult: The path and the extra server certificates.
        """
        now = now or datetime.now(timezone.utc)
        leaf = server_certs[0]
        # Unordered pool of candidate issuers sent by the server
        pool = []
        for cert in server_certs[1:]:
            if cert != leaf and all(cert != c for c, _ in pool):
                pool.append((cert, ORIGIN_SERVER))

        path, trusted, strict, ev_policy = self._find_path(leaf, pool, now, hostname)
        # No trusted path: extend the best path through AIA, one issuer at a time
        aia_fetches = 0
        while not trusted and self._aia_fetcher is not None and aia_fetches < MAX_AIA_FETCHES:
            top = path[-1][0]
            if is_self_signed(top):
                break
            issuer = self._aia_fetcher(top)
            aia_fetches += 1
            if issuer is None or any(issuer == c for c, _ in pool):
                break
            pool.append((issuer, ORIGIN_AIA))
            path, trusted, strict, ev_policy = self._find_path(leaf, pool, now, hostname)

        strict = strict and all(origin != ORIGIN_AIA for _, origin in path)
        return PathResult(path=path, trusted=trusted, strict=strict, ev_policy=ev_policy,
                          extra=self._extra_certificates(server_certs, path, trusted))

    def _find_path(self, leaf: x509.Certificate, pool: list, now: datetime,
                   hostname: str | None) -> tuple[list, bool, bool, str | None]:
        """
        Find a path the way Firefox does: first an EV path for each of the
        leaf's EV policies, then an ordinary path requiring 2048-bit RSA
        keys, then one allowing 1024-bit keys, all with Firefox's checks. If
        there is none, search again without the checks: Firefox would reject
        the chain, but the analysis can still report on it (e.g. an expired
        intermediate or a SHA-1 signature). If that fails too, return the
        best untrusted path.

        Returns:
            tuple: (path, trusted, strict, ev_policy)
        """
        for policy in self._leaf_ev_policies(leaf):
            path = self._search(leaf, pool, now, hostname, strict=True, policy=policy,
                                min_rsa_bits=rules.MIN_RSA_BITS)
            if path is not None:
                return path, True, True, policy
        for min_rsa_bits in (rules.MIN_RSA_BITS, rules.MIN_RSA_BITS_WEAK):
            path = self._search(leaf, pool, now, hostname, strict=True, min_rsa_bits=min_rsa_bits)
            if path is not None:
                return path, True, True, None
        best = []
        path = self._search(leaf, pool, now, hostname, strict=False, best=best)
        if path is not None:
            return path, True, False, None
        return (best[0] if best else [(leaf, ORIGIN_SERVER)]), False, False, None

    def _leaf_ev_policies(self, leaf: x509.Certificate) -> list:
        """The leaf's policies that Firefox knows as EV, in the leaf's order."""
        policies = []
        for policy in _policies(leaf) or []:
            if policy in self._ev_policies and policy not in policies:
                policies.append(policy)
        return policies

    def _is_trust_anchor(self, root: x509.Certificate, policy: str | None) -> bool:
        """
        Whether a root is trusted. For an EV policy, only roots Firefox's EV
        list registers for that policy are (any EV root for the CA/Browser
        Forum EV policy).
        """
        if policy is None:
            return True
        registered = self._ev_roots.get(root.fingerprint(hashes.SHA256()).hex())
        return registered is not None and (policy == CABF_EV_POLICY or policy in registered)

    @staticmethod
    def _extra_certificates(server_certs: list, path: list, trusted: bool) -> list:
        """
        Server certificates that are duplicates or unrelated to the chain.

        Cross-signed copies of the chain's root (same subject and key, other
        issuer) are not extra: servers send them on purpose for old clients.
        """
        top = path[-1][0]
        has_root = trusted or is_self_signed(top)
        root_identity = _identity(top) if has_root else None
        used = {cert for cert, _ in path}
        extra = []
        seen = set()
        for cert in server_certs:
            duplicate = cert in seen
            unrelated = cert not in used and _identity(cert) != root_identity
            if duplicate or unrelated:
                extra.append(cert)
            seen.add(cert)
        return extra

    def _candidates(self, cert: x509.Certificate, pool: list, policy: str | None = None):
        """
        Possible issuers of a certificate, in the order Firefox tries them:
        roots, server-sent certificates, preloaded intermediates.

        Yields:
            tuple: (certificate, origin, is_trust_anchor)
        """
        name = cert.issuer.public_bytes()
        seen = set()
        for root in self._roots.get(name, []):
            seen.add(root)
            # A root not trusted for the EV policy is an ordinary certificate
            # in that attempt (in practice a dead end: it is self-signed)
            yield root, ORIGIN_ROOTS, self._is_trust_anchor(root, policy)
        for candidate, origin in pool:
            if candidate not in seen and candidate.subject.public_bytes() == name:
                seen.add(candidate)
                yield candidate, origin, False
        for candidate in self._preloaded.get(name, []):
            if candidate not in seen:
                seen.add(candidate)
                yield candidate, ORIGIN_PRELOAD, False

    def _search(self, leaf: x509.Certificate, pool: list, now: datetime, hostname: str | None,
                strict: bool, best: Optional[list] = None, policy: str | None = None,
                min_rsa_bits: int = rules.MIN_RSA_BITS_WEAK) -> Optional[list]:
        """
        Depth-first search for a path from the leaf to a trust anchor.

        Args:
            leaf (x509.Certificate): The end-entity certificate.
            pool (list): (certificate, origin) tuples available as issuers.
            now (datetime): Verification time.
            hostname (str): The server's host name, for key pins.
            strict (bool): Apply Firefox's checks to the CA certificates.
            best (list): If given, receives the longest untrusted path found,
                preferring paths that end in a self-signed certificate.
            policy (str): EV policy OID the path must satisfy, or None.
            min_rsa_bits (int): Minimum RSA key size (strict mode). An attempt
                with more than 1024 bits also fails if the leaf's key is
                smaller, so that Firefox's next attempt is made.

        Returns:
            list: The trusted path, or None.
        """
        budget = [SEARCH_BUDGET]

        def record(path):
            if best is None:
                return
            score = (is_self_signed(path[-1][0]), len(path))
            if not best or score > best[1]:
                best[:] = [list(path), score]

        def allowed_below(candidate, path):
            """PathBuildingStep::Check, before the budget: name constraints and TLS features."""
            return name_constraints_permit(candidate, [c for c, _ in path]) and \
                rules.inherits_tls_features(path[-1][0], candidate)

        def acceptable(candidate, anchor, path):
            """BuildForward on the candidate: Firefox's checks on the issuer itself."""
            if not _usable_issuer(candidate, now, len(path) - 1, anchor, min_rsa_bits):
                return False
            if self.is_revoked(candidate):
                return False
            certs = [c for c, _ in path]
            if anchor:
                # NSSCertDBTrustDomain::IsChainValid
                return not self.distrusts(candidate, leaf) and \
                    self.has_valid_pins(hostname, certs + [candidate], now)
            return policy is None or _asserts_policy(candidate, policy, is_ca=True)

        def dfs(path, identities):
            record(path)
            if len(path) >= MAX_PATH_LENGTH:
                return None
            child = path[-1][0]
            for candidate, origin, anchor in self._candidates(child, pool, policy):
                identity = _identity(candidate)
                if identity in identities:
                    continue
                if strict and not allowed_below(candidate, path):
                    continue
                if budget[0] <= 0:
                    return None
                budget[0] -= 1
                if strict and not acceptable(candidate, anchor, path):
                    continue
                if not _signed_by(child, candidate):
                    continue
                if anchor:
                    return path + [(candidate, origin)]
                found = dfs(path + [(candidate, origin)], identities | {identity})
                if found:
                    return found
            return None

        if policy is not None and not _asserts_policy(leaf, policy, is_ca=False):
            return None
        if strict and min_rsa_bits > rules.MIN_RSA_BITS_WEAK and rules.key_problems(leaf, min_rsa_bits):
            return None
        return dfs([(leaf, ORIGIN_SERVER)], {_identity(leaf)})
