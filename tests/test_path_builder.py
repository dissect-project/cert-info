"""
Tests for the Firefox-style path builder (src/chain/path_builder.py).

The tests use a generated PKI so they run offline and do not depend on dates:

    O (old root) ──cross-signs──> A' (same subject and key as A)
    A (root) ──> I (intermediate) ──> L (leaf, example.com)

This is the shape of real cross-signs such as ISRG Root X1 / DST Root CA X3
or GlobalSign Root CA - R6 / R3.
"""

import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from src.chain import path_builder
from src.chain.path_builder import (
    ORIGIN_AIA, ORIGIN_PRELOAD, ORIGIN_ROOTS, ORIGIN_SERVER, PathBuilder,
)
from src.chain.pinning import pinset_for, spki_sha256
from src.trust.store import StaticPins, TrustStore

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, subject_key, issuer, issuer_key, ca=True,
          not_before=NOW - timedelta(days=365), not_after=NOW + timedelta(days=365)):
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


class TestPathBuilder(unittest.TestCase):
    """Firefox path building on a generated PKI."""

    @classmethod
    def setUpClass(cls):
        keys = {n: ec.generate_private_key(ec.SECP256R1()) for n in ("O", "A", "I", "L")}
        cls.keys = keys
        cls.O = _cert("Old Root", keys["O"], "Old Root", keys["O"])
        cls.A = _cert("Root A", keys["A"], "Root A", keys["A"])
        cls.A_cross = _cert("Root A", keys["A"], "Old Root", keys["O"])
        cls.I = _cert("Intermediate I", keys["I"], "Root A", keys["A"])
        cls.L = _cert("example.com", keys["L"], "Intermediate I", keys["I"], ca=False)

    def certs(self, result):
        return [cert for cert, _ in result.path]

    def origins(self, result):
        return [origin for _, origin in result.path]

    def test_stops_at_trusted_root_instead_of_cross_sign(self):
        """With A trusted, the cross-signed A' sent by the server is not used."""
        builder = PathBuilder(roots=[self.A, self.O], intermediates=[])
        result = builder.build([self.L, self.I, self.A_cross], now=NOW)
        self.assertTrue(result.trusted)
        self.assertEqual(self.certs(result), [self.L, self.I, self.A])
        self.assertEqual(self.origins(result), [ORIGIN_SERVER, ORIGIN_SERVER, ORIGIN_ROOTS])
        # A cross-signed copy of the chain's root is not an extra certificate
        self.assertEqual(result.extra, [])

    def test_unrelated_certificate_is_extra(self):
        builder = PathBuilder(roots=[self.A], intermediates=[])
        result = builder.build([self.L, self.I, self.O], now=NOW)
        self.assertEqual(self.certs(result), [self.L, self.I, self.A])
        self.assertEqual(result.extra, [self.O])

    def test_uses_cross_sign_when_only_old_root_is_trusted(self):
        """Without A in the store, the path goes through A' to the old root."""
        builder = PathBuilder(roots=[self.O], intermediates=[])
        result = builder.build([self.L, self.I, self.A_cross], now=NOW)
        self.assertTrue(result.trusted)
        self.assertEqual(self.certs(result), [self.L, self.I, self.A_cross, self.O])
        self.assertEqual(result.extra, [])

    def test_server_order_does_not_matter(self):
        builder = PathBuilder(roots=[self.A], intermediates=[])
        result = builder.build([self.L, self.A_cross, self.I], now=NOW)
        self.assertEqual(self.certs(result), [self.L, self.I, self.A])

    def test_missing_intermediate_comes_from_preload(self):
        """Firefox completes the chain with its preloaded intermediates."""
        builder = PathBuilder(roots=[self.A], intermediates=[self.I])
        result = builder.build([self.L], now=NOW)
        self.assertTrue(result.trusted)
        self.assertEqual(self.certs(result), [self.L, self.I, self.A])
        self.assertEqual(self.origins(result), [ORIGIN_SERVER, ORIGIN_PRELOAD, ORIGIN_ROOTS])

    def test_server_copy_of_root_is_not_extra_when_used(self):
        builder = PathBuilder(roots=[self.A], intermediates=[])
        result = builder.build([self.L, self.I, self.A], now=NOW)
        self.assertEqual(self.certs(result), [self.L, self.I, self.A])
        self.assertEqual(self.origins(result)[-1], ORIGIN_ROOTS)
        self.assertEqual(result.extra, [])

    def test_duplicates_are_extra(self):
        builder = PathBuilder(roots=[self.A], intermediates=[])
        result = builder.build([self.L, self.I, self.I], now=NOW)
        self.assertEqual(self.certs(result), [self.L, self.I, self.A])
        self.assertEqual(result.extra, [self.I])

    def test_expired_intermediate_is_skipped_for_valid_one(self):
        """An expired copy of I (same key) is skipped in favour of a valid one."""
        expired_i = _cert("Intermediate I", self.keys["I"], "Root A", self.keys["A"],
                          not_before=NOW - timedelta(days=800),
                          not_after=NOW - timedelta(days=1))
        builder = PathBuilder(roots=[self.A], intermediates=[self.I])
        result = builder.build([self.L, expired_i], now=NOW)
        self.assertTrue(result.trusted)
        self.assertEqual(self.certs(result), [self.L, self.I, self.A])
        self.assertEqual(result.extra, [expired_i])

    def test_expired_intermediate_is_kept_when_no_alternative(self):
        """Firefox would reject the chain, but it is still returned for analysis."""
        expired_i = _cert("Intermediate I", self.keys["I"], "Root A", self.keys["A"],
                          not_before=NOW - timedelta(days=800),
                          not_after=NOW - timedelta(days=1))
        builder = PathBuilder(roots=[self.A], intermediates=[])
        result = builder.build([self.L, expired_i], now=NOW)
        self.assertEqual(self.certs(result), [self.L, expired_i, self.A])

    def test_leaf_cannot_act_as_issuer(self):
        """A certificate without cA=true is not used as an intermediate."""
        not_ca = _cert("Intermediate I", self.keys["I"], "Root A", self.keys["A"], ca=False)
        builder = PathBuilder(roots=[self.A], intermediates=[self.I])
        result = builder.build([self.L, not_ca], now=NOW)
        self.assertEqual(self.certs(result), [self.L, self.I, self.A])

    def test_untrusted_self_signed_root(self):
        builder = PathBuilder(roots=[], intermediates=[])
        result = builder.build([self.L, self.I, self.A], now=NOW)
        self.assertFalse(result.trusted)
        self.assertEqual(self.certs(result), [self.L, self.I, self.A])
        self.assertEqual(self.origins(result)[-1], ORIGIN_SERVER)

    def test_incomplete_chain(self):
        builder = PathBuilder(roots=[self.A], intermediates=[])
        result = builder.build([self.L], now=NOW)
        self.assertFalse(result.trusted)
        self.assertEqual(self.certs(result), [self.L])

    def test_strict_flag(self):
        """strict tells whether Firefox would build the same path."""
        builder = PathBuilder(roots=[self.A], intermediates=[])
        self.assertTrue(builder.build([self.L, self.I], now=NOW).strict)
        expired_i = _cert("Intermediate I", self.keys["I"], "Root A", self.keys["A"],
                          not_before=NOW - timedelta(days=800),
                          not_after=NOW - timedelta(days=1))
        result = builder.build([self.L, expired_i], now=NOW)
        self.assertTrue(result.trusted)
        self.assertFalse(result.strict)
        self.assertFalse(builder.build([self.L], now=NOW).strict)

    def test_aia_path_is_not_strict(self):
        """Firefox does not fetch issuers through AIA."""
        builder = PathBuilder(roots=[self.A], intermediates=[],
                              aia_fetcher=lambda cert: self.I if cert == self.L else None)
        result = builder.build([self.L], now=NOW)
        self.assertTrue(result.trusted)
        self.assertFalse(result.strict)

    def test_aia_only_used_without_trusted_path(self):
        calls = []

        def fetcher(cert):
            calls.append(cert)
            return self.I if cert == self.L else None

        builder = PathBuilder(roots=[self.A], intermediates=[], aia_fetcher=fetcher)
        result = builder.build([self.L], now=NOW)
        self.assertTrue(result.trusted)
        self.assertEqual(self.certs(result), [self.L, self.I, self.A])
        self.assertEqual(self.origins(result)[1], ORIGIN_AIA)

        calls.clear()
        builder = PathBuilder(roots=[self.A], intermediates=[self.I], aia_fetcher=fetcher)
        builder.build([self.L], now=NOW)
        self.assertEqual(calls, [])


CUSTOM_EV = "1.3.6.1.4.1.99999.1"   # a CA-specific EV policy
CABF_EV = "2.23.140.1.1"
ANY = "2.5.29.32.0"


def _ev_cert(subject, subject_key, issuer, issuer_key, policies=None, ca=True):
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject)).issuer_name(_name(issuer))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=365))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if policies is not None:
        builder = builder.add_extension(x509.CertificatePolicies(
            [x509.PolicyInformation(x509.ObjectIdentifier(p), None) for p in policies]), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def _fp(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


class TestEVPathBuilding(unittest.TestCase):
    """
    Firefox builds an EV chain first. The shape of stripe.com and namecheap.com:
    root A is EV-registered only for the CA/Browser Forum EV policy, the older
    root O for the CA's own EV policy, and the server sends A cross-signed by O.
    A leaf whose first EV policy is the CA's own goes through the cross-sign.
    """

    @classmethod
    def setUpClass(cls):
        keys = {n: ec.generate_private_key(ec.SECP256R1()) for n in ("O", "A", "I", "L")}
        cls.keys = keys
        cls.O = _ev_cert("Old Root", keys["O"], "Old Root", keys["O"])
        cls.A = _ev_cert("Root A", keys["A"], "Root A", keys["A"])
        cls.A_cross = _ev_cert("Root A", keys["A"], "Old Root", keys["O"], [ANY])
        cls.I = _ev_cert("EV CA", keys["I"], "Root A", keys["A"], [ANY, CABF_EV])
        cls.ev_roots = {_fp(cls.O): {CUSTOM_EV}, _fp(cls.A): {CABF_EV}}

    def leaf(self, policies):
        return _ev_cert("example.com", self.keys["L"], "EV CA", self.keys["I"], policies, ca=False)

    def build(self, leaf, intermediate=None, ev_roots=None):
        builder = PathBuilder(roots=[self.A, self.O], intermediates=[],
                              ev_roots=self.ev_roots if ev_roots is None else ev_roots)
        return builder.build([leaf, intermediate or self.I, self.A_cross], now=NOW)

    def test_ca_specific_ev_policy_goes_through_cross_sign(self):
        result = self.build(self.leaf([CUSTOM_EV, CABF_EV]))
        self.assertEqual([c for c, _ in result.path], [result.path[0][0], self.I, self.A_cross, self.O])
        self.assertEqual(result.ev_policy, CUSTOM_EV)
        self.assertTrue(result.strict)
        self.assertEqual(result.extra, [])

    def test_policy_order_matters(self):
        """With the CA/Browser Forum policy first, the newer root is EV-trusted."""
        result = self.build(self.leaf([CABF_EV, CUSTOM_EV]))
        self.assertEqual([c for c, _ in result.path][1:], [self.I, self.A])
        self.assertEqual(result.ev_policy, CABF_EV)

    def test_intermediate_must_assert_policy(self):
        """Without the policy (or anyPolicy) in the intermediate, no EV chain: ordinary chain."""
        no_policy = _ev_cert("EV CA", self.keys["I"], "Root A", self.keys["A"])
        result = self.build(self.leaf([CUSTOM_EV, CABF_EV]), intermediate=no_policy)
        self.assertEqual([c for c, _ in result.path][1:], [no_policy, self.A])
        self.assertIsNone(result.ev_policy)

    def test_unregistered_policy_falls_back_to_cabf(self):
        ev_roots = {_fp(self.O): {"1.3.6.1.4.1.99999.2"}, _fp(self.A): {CABF_EV}}
        result = self.build(self.leaf([CUSTOM_EV, CABF_EV]), ev_roots=ev_roots)
        self.assertEqual([c for c, _ in result.path][1:], [self.I, self.A])
        self.assertEqual(result.ev_policy, CABF_EV)

    def test_non_ev_leaf_uses_ordinary_chain(self):
        result = self.build(self.leaf(["2.23.140.1.2.1"]))
        self.assertEqual([c for c, _ in result.path][1:], [self.I, self.A])
        self.assertIsNone(result.ev_policy)

    def test_without_ev_data_ordinary_chain(self):
        result = self.build(self.leaf([CUSTOM_EV, CABF_EV]), ev_roots={})
        self.assertEqual([c for c, _ in result.path][1:], [self.I, self.A])


def _custom(subject, subject_key, issuer, issuer_key, ca=True, extensions=(), expired=False,
            not_before=None):
    """A certificate with extra extensions (value, critical)."""
    start = not_before or (NOW - timedelta(days=800) if expired else NOW - timedelta(days=30))
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject)).issuer_name(_name(issuer))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(NOW - timedelta(days=1) if expired else NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    for value, critical in extensions:
        builder = builder.add_extension(value, critical=critical)
    return builder.sign(issuer_key, hashes.SHA256())


class TestFirefoxChecks(unittest.TestCase):
    """Checks mozilla::pkix applies while building, which make it try other paths."""

    @classmethod
    def setUpClass(cls):
        cls.k = {n: ec.generate_private_key(ec.SECP256R1()) for n in ("R", "R2", "I", "L")}
        cls.R = _custom("Root", cls.k["R"], "Root", cls.k["R"])
        cls.R2 = _custom("Root 2", cls.k["R2"], "Root 2", cls.k["R2"])
        cls.R_cross = _custom("Root", cls.k["R"], "Root 2", cls.k["R2"])  # Root, cross-signed by Root 2
        cls.I = _custom("CA", cls.k["I"], "Root", cls.k["R"])
        cls.L = _custom("example.com", cls.k["L"], "CA", cls.k["I"], ca=False)

    def test_expired_root_is_skipped_for_cross_sign(self):
        """Firefox checks the root's validity too, and then tries the cross-signed copy."""
        expired_root = _custom("Root", self.k["R"], "Root", self.k["R"], expired=True)
        builder = PathBuilder(roots=[expired_root, self.R2], intermediates=[])
        result = builder.build([self.L, self.I, self.R_cross], now=NOW)
        self.assertTrue(result.strict)
        self.assertEqual([c for c, _ in result.path], [self.L, self.I, self.R_cross, self.R2])

    def test_root_without_server_auth_is_skipped(self):
        client_only = x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH])
        root = _custom("Root", self.k["R"], "Root", self.k["R"], extensions=[(client_only, False)])
        builder = PathBuilder(roots=[root, self.R2], intermediates=[])
        result = builder.build([self.L, self.I, self.R_cross], now=NOW)
        self.assertEqual([c for c, _ in result.path][-1], self.R2)

    def test_any_eku_intermediate_is_not_usable(self):
        any_eku = x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE])
        intermediate = _custom("CA", self.k["I"], "Root", self.k["R"], extensions=[(any_eku, False)])
        result = PathBuilder(roots=[self.R], intermediates=[]).build([self.L, intermediate], now=NOW)
        self.assertTrue(result.trusted)
        self.assertFalse(result.strict)

    def test_unknown_critical_extension_makes_intermediate_unusable(self):
        unknown = x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4"), b"\x05\x00")
        intermediate = _custom("CA", self.k["I"], "Root", self.k["R"], extensions=[(unknown, True)])
        result = PathBuilder(roots=[self.R], intermediates=[self.I]).build([self.L, intermediate], now=NOW)
        self.assertTrue(result.strict)
        self.assertEqual([c for c, _ in result.path][1], self.I)

    def test_must_staple_is_inherited(self):
        """A certificate must repeat its issuer's TLS Feature extension."""
        must_staple = (x509.TLSFeature([x509.TLSFeatureType.status_request]), False)
        intermediate = _custom("CA", self.k["I"], "Root", self.k["R"], extensions=[must_staple])
        builder = PathBuilder(roots=[self.R], intermediates=[])
        self.assertFalse(builder.build([self.L, intermediate], now=NOW).strict)
        leaf = _custom("example.com", self.k["L"], "CA", self.k["I"], ca=False, extensions=[must_staple])
        self.assertTrue(builder.build([leaf, intermediate], now=NOW).strict)

    def test_leaf_problems_do_not_change_the_path(self):
        """mozilla::pkix reports problems of the leaf itself after building the path."""
        expired_leaf = _custom("example.com", self.k["L"], "CA", self.k["I"], ca=False, expired=True)
        result = PathBuilder(roots=[self.R], intermediates=[]).build([expired_leaf, self.I], now=NOW)
        self.assertTrue(result.strict)

    def test_2048_bit_path_is_preferred(self):
        """
        Firefox first requires 2048-bit RSA keys in every certificate, roots
        included, then accepts 1024: the path to the 1024-bit root comes
        first but the other one is chosen.
        """
        weak = rsa.generate_private_key(65537, 1024)
        weak_root = _custom("Weak Root", weak, "Weak Root", weak)
        mid_under_weak = _custom("CA", self.k["I"], "Weak Root", weak)
        mid_under_r2 = _custom("CA", self.k["I"], "Root 2", self.k["R2"])
        builder = PathBuilder(roots=[weak_root, self.R2], intermediates=[])
        result = builder.build([self.L, mid_under_weak, mid_under_r2], now=NOW)
        self.assertEqual([c for c, _ in result.path][1:], [mid_under_r2, self.R2])
        # Without the alternative, the 1024-bit attempt accepts the weak root
        result = builder.build([self.L, mid_under_weak], now=NOW)
        self.assertTrue(result.strict)
        self.assertEqual([c for c, _ in result.path][-1], weak_root)

    def test_self_issued_certificates_are_name_constrained(self):
        """RFC 5280 exempts self-issued CA certificates; mozilla::pkix does not."""
        allowed = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Allowed")])
        constraints = x509.NameConstraints(permitted_subtrees=[x509.DirectoryName(allowed)],
                                           excluded_subtrees=None)
        root = _custom("Root", self.k["R"], "Root", self.k["R"], extensions=[(constraints, True)])
        # Key rollover certificate: subject = issuer = "Root", another key
        rollover = _custom("Root", self.k["I"], "Root", self.k["R"])
        leaf = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Allowed"),
                                         x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]))
                .issuer_name(_name("Root"))
                .public_key(self.k["L"].public_key()).serial_number(1)
                .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=30))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(self.k["I"], hashes.SHA256()))
        result = PathBuilder(roots=[root], intermediates=[]).build([leaf, rollover], now=NOW)
        self.assertTrue(result.trusted)
        self.assertFalse(result.strict)


class TestSearchBudget(unittest.TestCase):
    """mozilla::pkix limits the number of candidate issuers it examines."""

    @classmethod
    def setUpClass(cls):
        cls.k = {n: ec.generate_private_key(ec.SECP256R1()) for n in ("R", "I", "L")}
        cls.R = _custom("Root", cls.k["R"], "Root", cls.k["R"])
        cls.I = _custom("CA", cls.k["I"], "Root", cls.k["R"])
        cls.L = _custom("example.com", cls.k["L"], "CA", cls.k["I"], ca=False)

    def test_search_stops_when_the_budget_runs_out(self):
        builder = PathBuilder(roots=[self.R], intermediates=[])
        with mock.patch.object(path_builder, "SEARCH_BUDGET", 2):
            self.assertTrue(builder.build([self.L, self.I], now=NOW).strict)
        with mock.patch.object(path_builder, "SEARCH_BUDGET", 1):
            self.assertFalse(builder.build([self.L, self.I], now=NOW).strict)

    def test_candidates_outside_name_constraints_are_not_counted(self):
        """Like Firefox, the budget is spent after the name constraint check."""
        constraints = x509.NameConstraints(permitted_subtrees=[x509.DNSName("other.example")],
                                           excluded_subtrees=None)
        constrained = _custom("CA", self.k["I"], "Root", self.k["R"], extensions=[(constraints, True)])
        builder = PathBuilder(roots=[self.R], intermediates=[self.I])
        with mock.patch.object(path_builder, "SEARCH_BUDGET", 2):
            result = builder.build([self.L, constrained], now=NOW)
        self.assertTrue(result.strict)
        self.assertEqual([c for c, _ in result.path][1], self.I)


class TestKeyPins(unittest.TestCase):
    """Firefox's static key pins, checked when a trust anchor is reached."""

    @classmethod
    def setUpClass(cls):
        cls.k = {n: ec.generate_private_key(ec.SECP256R1()) for n in ("R", "R2", "I", "L")}
        cls.R = _custom("Root", cls.k["R"], "Root", cls.k["R"])
        cls.R2 = _custom("Root 2", cls.k["R2"], "Root 2", cls.k["R2"])
        cls.I = _custom("CA", cls.k["I"], "Root", cls.k["R"])
        cls.I_cross = _custom("CA", cls.k["I"], "Root 2", cls.k["R2"])
        cls.L = _custom("www.pinned.example", cls.k["L"], "CA", cls.k["I"], ca=False)

    def pins(self, pinned_root, test_mode=False, expiration=NOW + timedelta(days=30)):
        entries = {"pinned.example": (True, test_mode, {spki_sha256(pinned_root)})}
        return StaticPins(entries, expiration)

    def build(self, pins, hostname="www.pinned.example"):
        builder = PathBuilder(roots=[self.R, self.R2], intermediates=[], pins=pins)
        return builder.build([self.L, self.I, self.I_cross], now=NOW, hostname=hostname)

    def test_path_to_pinned_root_is_chosen(self):
        result = self.build(self.pins(self.R2))
        self.assertTrue(result.strict)
        self.assertEqual([c for c, _ in result.path][-1], self.R2)

    def test_no_pinned_key_is_rejected(self):
        other_key = ec.generate_private_key(ec.SECP256R1())
        other = _custom("Other", other_key, "Other", other_key)
        result = PathBuilder(roots=[self.R], intermediates=[], pins=self.pins(other)).build(
            [self.L, self.I], now=NOW, hostname="www.pinned.example")
        self.assertTrue(result.trusted)
        self.assertFalse(result.strict)

    def test_pins_only_apply_to_their_hosts(self):
        result = self.build(self.pins(self.R2), hostname="www.other.example")
        self.assertEqual([c for c, _ in result.path][-1], self.R)

    def test_test_mode_and_expired_pins_are_not_enforced(self):
        self.assertEqual([c for c, _ in self.build(self.pins(self.R2, test_mode=True)).path][-1], self.R)
        expired = self.pins(self.R2, expiration=NOW - timedelta(days=1))
        self.assertEqual([c for c, _ in self.build(expired).path][-1], self.R)

    def test_host_lookup(self):
        pinset = {b"x"}
        pins = StaticPins({"example.com": (False, False, pinset), "sub.example.com": (True, False, pinset)},
                          NOW + timedelta(days=1))
        self.assertEqual(pinset_for(pins, "example.com", NOW), pinset)
        self.assertIsNone(pinset_for(pins, "www.example.com", NOW))  # no includeSubdomains
        self.assertEqual(pinset_for(pins, "a.sub.example.com.", NOW), pinset)

    def test_bundled_pins(self):
        pins = TrustStore.mozilla().pins
        if pins.expiration is None or NOW > pins.expiration:
            self.skipTest("bundled pins missing or expired")
        self.assertIsNotNone(pinset_for(pins, "addons.mozilla.org", NOW))


if __name__ == "__main__":
    unittest.main()
