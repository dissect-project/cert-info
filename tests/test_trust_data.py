"""
Tests for the Mozilla trust data applied during path building: the root store
generated from certdata.txt and its distrust dates, OneCRL, name constraints,
and the leaf Key Usage check. They run offline.
"""

import base64
import hashlib
import importlib.util
import ipaddress
import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from src.chain.name_constraints import constraints_of, path_violations, violates
from src.chain.path_builder import PathBuilder
from src.trust.store import MOZILLA_ROOTS, OneCRL, load_pem_bundle
from src.validation import certificate_validator as cv
from src.validation import revocation, transparency
from src.validation.chain_validator import DISTRUSTED_ROOT, NAME_CONSTRAINTS, ONECRL_REVOKED, ChainValidator

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
KEYS = {n: ec.generate_private_key(ec.SECP256R1()) for n in ("R", "R2", "I", "I2", "L")}


def _name(cn, org=None):
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org:
        attributes.insert(0, x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    return x509.Name(attributes)


def _cert(subject, key, issuer, issuer_key, ca=True, san=None, ips=None, constraints=None,
          not_before=NOW - timedelta(days=30), key_usage=None, subject_name=None, issuer_name=None):
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name or _name(subject)).issuer_name(issuer_name or _name(issuer))
        .public_key(KEYS[key].public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before).not_valid_after(NOW + timedelta(days=60))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    names = [x509.DNSName(n) for n in san or []] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips or []]
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    if constraints is not None:
        builder = builder.add_extension(constraints, critical=True)
    if key_usage is not None:
        flags = dict.fromkeys(["digital_signature", "content_commitment", "key_encipherment",
                               "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign",
                               "encipher_only", "decipher_only"], False)
        flags.update(key_usage)
        builder = builder.add_extension(x509.KeyUsage(**flags), critical=True)
    return builder.sign(KEYS[issuer_key], hashes.SHA256())


def _fp(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def _paths(result):
    return [cert for cert, _ in result.path]


class TestCertdataParser(unittest.TestCase):
    """scripts/update_mozilla_roots.py"""

    @classmethod
    def setUpClass(cls):
        path = os.path.join(os.path.dirname(__file__), "..", "scripts", "update_mozilla_roots.py")
        spec = importlib.util.spec_from_file_location("update_mozilla_roots", path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    @staticmethod
    def _octal(data: bytes) -> str:
        return "".join(f"\\{byte:03o}" for byte in data)

    def _object(self, cert, server_trust, distrust=None):
        der = cert.public_bytes(serialization.Encoding.DER)
        sha1 = hashes.Hash(hashes.SHA1())
        sha1.update(der)
        distrust_line = (f"CKA_NSS_SERVER_DISTRUST_AFTER MULTILINE_OCTAL\n{self._octal(distrust)}\nEND"
                         if distrust else "CKA_NSS_SERVER_DISTRUST_AFTER CK_BBOOL CK_FALSE")
        return (f"# Certificate\nCKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\n"
                f"CKA_VALUE MULTILINE_OCTAL\n{self._octal(der)}\nEND\n{distrust_line}\n\n"
                f"# Trust\nCKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST\n"
                f"CKA_CERT_SHA1_HASH MULTILINE_OCTAL\n{self._octal(sha1.finalize())}\nEND\n"
                f"CKA_TRUST_SERVER_AUTH CK_TRUST {server_trust}\n\n")

    def test_trusted_roots_and_distrust_dates(self):
        trusted = _cert("Trusted Root", "R", "Trusted Root", "R")
        email_only = _cert("Email Root", "R2", "Email Root", "R2")
        distrusted = _cert("Distrusted Root", "I", "Distrusted Root", "I")
        certdata = (self._object(trusted, "CKT_NSS_TRUSTED_DELEGATOR")
                    + self._object(email_only, "CKT_NSS_MUST_VERIFY_TRUST")
                    + self._object(distrusted, "CKT_NSS_TRUSTED_DELEGATOR", b"241130235959Z"))
        roots, distrust = self.module.roots_and_distrust(certdata)
        self.assertEqual(sorted(_fp(c) for c in roots), sorted([_fp(trusted), _fp(distrusted)]))
        self.assertEqual(list(distrust), [_fp(distrusted)])
        self.assertEqual(distrust[_fp(distrusted)][0], datetime(2024, 11, 30, 23, 59, 59, tzinfo=timezone.utc))

    def test_bundled_root_store_matches_firefox_policy(self):
        """Roots Mozilla removed for websites (e.g. DigiCert Global Root CA) are not trusted."""
        subjects = {c.subject.rfc4514_string() for c in load_pem_bundle(MOZILLA_ROOTS)}
        self.assertNotIn("CN=DigiCert Global Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US", subjects)
        self.assertIn("CN=ISRG Root X1,O=Internet Security Research Group,C=US", subjects)


def _load_script(name):
    path = os.path.join(os.path.dirname(__file__), "..", "scripts", name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestFirefoxHeaderParsers(unittest.TestCase):
    """scripts/update_firefox_ct_logs.py and scripts/update_firefox_pins.py"""

    CT_KNOWN_LOGS = """
static const PRTime kCTExpirationTime = INT64_C(1799784947000000);
const CTLogInfo kCTLogList[] = {
    {"Google Argon", CTLogState::Admissible, CTLogFormat::RFC6962,
     1727734767000,  // 2024-09-30T22:19:27Z
     0,              // operated by Google
     "\\x30\\x03"
     "\\x01\\x02\\x03",
     5},
    {"Sectigo Old", CTLogState::Retired, CTLogFormat::Tiled,
     1700000000000,  // 2023-11-14T22:13:20Z
     1,              // operated by Sectigo
     "\\x30\\x01\\x00",
     3},
};
const CTLogOperatorInfo kCTLogOperatorList[] = {
    {"Google", 0},
    {"Sectigo", 3},
};
"""

    STATIC_PINS = """
static const char kRoot_AFingerprint[] =
  "AAAA";
static const char kRoot_BFingerprint[] =
  "BBBB";
static const char* const kPinset_mozilla_services_Data[] = {
  kRoot_AFingerprint,
  kRoot_BFingerprint,
};
static const TransportSecurityPreload kPublicKeyPinningPreloadList[] = {
  { "addons.mozilla.org", true, false, true, 1, &kPinset_mozilla_services },
  { "test.example", false, true, false, -1, &kPinset_mozilla_services },
};
static const PRTime kPreloadPKPinsExpirationTime = INT64_C(1801848315576000);
"""

    def test_ct_logs(self):
        data = _load_script("update_firefox_ct_logs").parse(self.CT_KNOWN_LOGS)
        self.assertEqual(data["expiration"], "2027-01-12T20:15:47Z")
        argon, sectigo = data["logs"]
        self.assertEqual((argon["name"], argon["state"], argon["format"], argon["operator_id"]),
                         ("Google Argon", "Admissible", "RFC6962", 0))
        self.assertEqual(base64.b64decode(argon["key"]), b"\x30\x03\x01\x02\x03")
        self.assertEqual(base64.b64decode(argon["log_id"]), hashlib.sha256(b"\x30\x03\x01\x02\x03").digest())
        self.assertEqual((sectigo["state"], sectigo["format"], sectigo["operator_id"]), ("Retired", "Tiled", 3))

    def test_pins(self):
        data = _load_script("update_firefox_pins").parse(self.STATIC_PINS)
        self.assertEqual(data["pinsets"], {"mozilla_services": ["AAAA", "BBBB"]})
        self.assertEqual(data["entries"][0], {"host": "addons.mozilla.org", "include_subdomains": True,
                                              "test_mode": False, "pinset": "mozilla_services"})
        self.assertTrue(data["entries"][1]["test_mode"])


class TestDistrustDates(unittest.TestCase):
    """A root's distrust date applies to leaves issued after it."""

    @classmethod
    def setUpClass(cls):
        cls.R = _cert("Root", "R", "Root", "R")
        cls.R2 = _cert("Root 2", "R2", "Root 2", "R2")
        cls.I = _cert("CA", "I", "Root", "R")
        cls.I_cross = _cert("CA", "I", "Root 2", "R2")  # same CA, also under Root 2
        cls.distrust = {_fp(cls.R): NOW - timedelta(days=10)}

    def leaf(self, issued):
        return _cert("example.com", "L", "CA", "I", ca=False, san=["example.com"], not_before=issued)

    def test_leaf_issued_before_distrust_date(self):
        builder = PathBuilder([self.R], [], distrust=self.distrust)
        result = builder.build([self.leaf(NOW - timedelta(days=20)), self.I], now=NOW)
        self.assertTrue(result.strict)
        self.assertEqual(_paths(result)[-1], self.R)

    def test_leaf_issued_after_distrust_date_is_rejected(self):
        builder = PathBuilder([self.R], [], distrust=self.distrust)
        result = builder.build([self.leaf(NOW - timedelta(days=5)), self.I], now=NOW)
        self.assertFalse(result.strict)

    def test_other_path_is_used(self):
        """Firefox tries other paths: here through the other root."""
        builder = PathBuilder([self.R, self.R2], [], distrust=self.distrust)
        result = builder.build([self.leaf(NOW - timedelta(days=5)), self.I, self.I_cross], now=NOW)
        self.assertTrue(result.strict)
        self.assertEqual(_paths(result)[1:], [self.I_cross, self.R2])

    def test_reported_on_the_root(self):
        builder = PathBuilder([self.R], [], distrust=self.distrust)
        leaf = self.leaf(NOW - timedelta(days=5))
        chain = [{"id": cv.LEAF, "origin": "Server", "cert": leaf},
                 {"id": cv.INTERMEDIATE, "origin": "Server", "cert": self.I},
                 {"id": cv.ROOT, "origin": "Mozilla CA Bundle", "cert": self.R}]
        response = _validate_chain(chain, builder)
        self.assertIn(DISTRUSTED_ROOT.format(date=NOW - timedelta(days=10)), response["chain"][2]["issues"])
        self.assertEqual(response["status"], "invalid")


class TestOneCRL(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.R = _cert("Root", "R", "Root", "R")
        cls.I_revoked = _cert("CA", "I", "Root", "R")
        cls.I_reissued = _cert("CA", "I", "Root", "R")  # same CA, new certificate
        cls.L = _cert("example.com", "L", "CA", "I", ca=False, san=["example.com"])

    @staticmethod
    def by_serial(cert):
        serial = cert.serial_number.to_bytes((cert.serial_number.bit_length() + 8) // 8, "big")
        return OneCRL(issuer_serial=[(base64.b64encode(cert.issuer.public_bytes()).decode(),
                                      base64.b64encode(serial).decode())])

    @staticmethod
    def by_key(cert):
        spki = cert.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(spki)
        return OneCRL(subject_pubkey_hash=[(base64.b64encode(cert.subject.public_bytes()).decode(),
                                            base64.b64encode(digest.finalize()).decode())])

    def test_matching(self):
        self.assertTrue(self.by_serial(self.I_revoked).revokes(self.I_revoked))
        self.assertFalse(self.by_serial(self.I_revoked).revokes(self.I_reissued))
        self.assertTrue(self.by_key(self.I_revoked).revokes(self.I_reissued))  # same subject and key

    def test_revoked_intermediate_is_skipped(self):
        builder = PathBuilder([self.R], [self.I_reissued], onecrl=self.by_serial(self.I_revoked))
        result = builder.build([self.L, self.I_revoked], now=NOW)
        self.assertTrue(result.strict)
        self.assertEqual(_paths(result)[1:], [self.I_reissued, self.R])

    def test_revoked_without_alternative_is_reported(self):
        builder = PathBuilder([self.R], [], onecrl=self.by_serial(self.I_revoked))
        result = builder.build([self.L, self.I_revoked], now=NOW)
        self.assertFalse(result.strict)
        chain = [{"id": cv.LEAF, "origin": "Server", "cert": self.L},
                 {"id": cv.INTERMEDIATE, "origin": "Server", "cert": self.I_revoked},
                 {"id": cv.ROOT, "origin": "Mozilla CA Bundle", "cert": self.R}]
        response = _validate_chain(chain, builder, strict=False)
        self.assertIn(ONECRL_REVOKED, response["chain"][1]["issues"])
        self.assertEqual(response["chain"][1]["status"], "invalid")


def _constraints(permitted=None, excluded=None):
    return x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=excluded)


def _leaf(san=None, ips=None, cn="host"):
    return _cert(cn, "L", "CA", "I", ca=False, san=san, ips=ips)


class TestNameConstraints(unittest.TestCase):

    def test_permitted_dns(self):
        c = _constraints(permitted=[x509.DNSName("example.com")])
        self.assertFalse(violates(c, _leaf(["example.com", "www.example.com"]), True))
        self.assertTrue(violates(c, _leaf(["www.example.com", "evil.com"]), True))
        self.assertTrue(violates(c, _leaf(["notexample.com"]), True))

    def test_leading_dot_means_subdomains_only(self):
        c = _constraints(permitted=[x509.DNSName(".example.com")])
        self.assertFalse(violates(c, _leaf(["a.example.com"]), True))
        self.assertTrue(violates(c, _leaf(["example.com"]), True))

    def test_excluded_dns(self):
        c = _constraints(excluded=[x509.DNSName("bank.example")])
        self.assertTrue(violates(c, _leaf(["login.bank.example"]), True))
        self.assertFalse(violates(c, _leaf(["shop.example"]), True))

    def test_wildcards(self):
        permitted = _constraints(permitted=[x509.DNSName("example.com")])
        self.assertFalse(violates(permitted, _leaf(["*.example.com"]), True))
        self.assertTrue(violates(_constraints(permitted=[x509.DNSName("www.example.com")]),
                                 _leaf(["*.example.com"]), True))
        excluded = _constraints(excluded=[x509.DNSName("secret.example.com")])
        self.assertTrue(violates(excluded, _leaf(["*.example.com"]), True))  # covers secret.example.com

    def test_ip_addresses(self):
        c = _constraints(permitted=[x509.IPAddress(ipaddress.ip_network("192.0.2.0/24"))])
        self.assertFalse(violates(c, _leaf(ips=["192.0.2.10"]), True))
        self.assertTrue(violates(c, _leaf(ips=["198.51.100.1"]), True))
        self.assertFalse(violates(c, _leaf(["example.com"]), True))  # no IP: not restricted

    def test_directory_name(self):
        c = _constraints(permitted=[x509.DirectoryName(
            x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Org")]))])
        inside = _cert("host", "L", "CA", "I", ca=False, subject_name=_name("host", org="Example Org"))
        outside = _cert("host", "L", "CA", "I", ca=False, subject_name=_name("host", org="Other Org"))
        self.assertFalse(violates(c, inside, True))
        self.assertTrue(violates(c, outside, True))

    def test_common_name_used_without_san(self):
        c = _constraints(permitted=[x509.DNSName("example.com")])
        self.assertTrue(violates(c, _leaf(cn="evil.com"), True))
        self.assertFalse(violates(c, _leaf(cn="www.example.com"), True))

    def leaf_with(self, names=None, subject=None):
        """A leaf with any Subject Alternative Names (None: no SAN extension)."""
        builder = (x509.CertificateBuilder().subject_name(subject if subject is not None else _name("host"))
                   .issuer_name(_name("CA")).public_key(KEYS["L"].public_key()).serial_number(1)
                   .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=30)))
        if names is not None:
            builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
        return builder.sign(KEYS["I"], hashes.SHA256())

    def test_excluded_directory_names_reject_everything(self):
        """mozilla::pkix does not support excluded directoryName subtrees."""
        c = _constraints(excluded=[x509.DirectoryName(x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Evil")]))])
        self.assertTrue(violates(c, _leaf(["example.com"]), True))

    def test_directory_names_compare_encodings(self):
        """PrintableString and UTF8String are interchangeable; other string types are not."""
        def org(value, string_type):
            return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, value, _type=string_type)])
        from cryptography.x509.name import _ASN1Type
        c = _constraints(permitted=[x509.DirectoryName(org("Example", _ASN1Type.UTF8String))])
        self.assertFalse(violates(c, self.leaf_with([x509.DNSName("a.example")],
                                                    org("Example", _ASN1Type.PrintableString)), True))
        self.assertTrue(violates(c, self.leaf_with([x509.DNSName("a.example")],
                                                   org("Example", _ASN1Type.IA5String)), True))

    def test_empty_subject_is_checked(self):
        c = _constraints(permitted=[x509.DirectoryName(_name("host", org="Example Org"))])
        self.assertTrue(violates(c, self.leaf_with([x509.DNSName("a.example")], x509.Name([])), True))

    def test_email_addresses(self):
        c = _constraints(permitted=[x509.RFC822Name("example.com")])
        self.assertFalse(violates(c, self.leaf_with([x509.RFC822Name("a@example.com")]), True))
        self.assertTrue(violates(c, self.leaf_with([x509.RFC822Name("a@sub.example.com")]), True))
        domain = _constraints(permitted=[x509.RFC822Name(".example.com")])
        self.assertFalse(violates(domain, self.leaf_with([x509.RFC822Name("a@sub.example.com")]), True))
        mailbox = _constraints(excluded=[x509.RFC822Name("ceo@example.com")])
        self.assertTrue(violates(mailbox, self.leaf_with([x509.RFC822Name("CEO@example.com")]), True))

    def test_subject_email_address_without_san(self):
        """Without a SAN extension, the subject's emailAddress attributes are checked."""
        c = _constraints(permitted=[x509.RFC822Name("example.com")])
        subject = x509.Name([x509.NameAttribute(NameOID.EMAIL_ADDRESS, "a@evil.com")])
        self.assertTrue(violates(c, self.leaf_with(None, subject), True))
        self.assertFalse(violates(c, self.leaf_with([x509.DNSName("a.example")], subject), True))

    def test_unsupported_name_types(self):
        """A URI is rejected only if the constraints have a URI subtree."""
        # (no Common Name: it would be checked as a DNS name)
        uri_leaf = self.leaf_with([x509.UniformResourceIdentifier("https://example.com/")],
                                  x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example")]))
        self.assertTrue(violates(_constraints(permitted=[x509.UniformResourceIdentifier(".example.com")]),
                                 uri_leaf, True))
        self.assertFalse(violates(_constraints(permitted=[x509.DNSName("example.com")]), uri_leaf, True))

    def test_only_the_last_common_name_counts(self):
        c = _constraints(permitted=[x509.DNSName("example.com")])
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil.com"),
                             x509.NameAttribute(NameOID.COMMON_NAME, "www.example.com")])
        self.assertFalse(violates(c, self.leaf_with(None, subject), True))
        reversed_subject = x509.Name(list(reversed(list(subject))))
        self.assertTrue(violates(c, self.leaf_with(None, reversed_subject), True))

    def test_invalid_dns_name_is_rejected(self):
        c = _constraints(permitted=[x509.DNSName("example.com")])
        self.assertTrue(violates(c, self.leaf_with([x509.DNSName("bad name.example.com")]), True))

    def test_imposed_constraints_on_tubitak_root(self):
        """NSS limits the TUBITAK root (no extension) to .tr."""
        tubitak = [c for c in load_pem_bundle(MOZILLA_ROOTS)
                   if "TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1" in c.subject.rfc4514_string()]
        if not tubitak:
            self.skipTest("TUBITAK root not in the bundle")
        constraints = constraints_of(tubitak[0])
        self.assertIsNotNone(constraints)
        self.assertTrue(violates(constraints, _leaf(["example.com"]), True))
        self.assertFalse(violates(constraints, _leaf(["www.example.com.tr"]), True))

    def test_path_building_avoids_violating_path(self):
        """Firefox tries other paths: here an unconstrained copy of the intermediate."""
        root = _cert("Root", "R", "Root", "R")
        root2 = _cert("Root 2", "R2", "Root 2", "R2")
        constrained = _cert("CA", "I", "Root", "R", constraints=_constraints(permitted=[x509.DNSName("example.org")]))
        unconstrained = _cert("CA", "I", "Root 2", "R2")
        leaf = _leaf(["example.com"])
        builder = PathBuilder([root, root2], [])
        result = builder.build([leaf, constrained, unconstrained], now=NOW)
        self.assertTrue(result.strict)
        self.assertEqual(_paths(result)[1:], [unconstrained, root2])
        result = PathBuilder([root], []).build([leaf, constrained], now=NOW)
        self.assertFalse(result.strict)
        self.assertEqual(path_violations(_paths(result)), [0])

    def test_reported_on_the_certificate(self):
        root = _cert("Root", "R", "Root", "R", constraints=_constraints(permitted=[x509.DNSName("example.org")]))
        intermediate = _cert("CA", "I", "Root", "R")
        leaf = _leaf(["example.com"])
        chain = [{"id": cv.LEAF, "origin": "Server", "cert": leaf},
                 {"id": cv.INTERMEDIATE, "origin": "Server", "cert": intermediate},
                 {"id": cv.ROOT, "origin": "Mozilla CA Bundle", "cert": root}]
        response = _validate_chain(chain, PathBuilder([root], []), strict=False, domain="example.com")
        self.assertIn(NAME_CONSTRAINTS, response["chain"][0]["issues"])
        self.assertNotIn(NAME_CONSTRAINTS, response["chain"][1]["issues"])


class TestLeafKeyUsage(unittest.TestCase):

    def check(self, key_usage):
        leaf = _cert("example.com", "L", "CA", "I", ca=False, san=["example.com"], key_usage=key_usage)
        issues = []
        return cv._check_tls_key_usage(leaf, issues), issues

    def test_tls_key_usages_are_accepted(self):
        for usage in ("digital_signature", "key_encipherment", "key_agreement"):
            with self.subTest(usage=usage):
                self.assertEqual(self.check({usage: True}), (True, []))

    def test_other_key_usage_is_rejected(self):
        self.assertEqual(self.check({"content_commitment": True}), (False, [cv.NOT_TLS_KEY_USAGE]))

    def test_no_key_usage_is_accepted(self):
        self.assertEqual(self.check(None), (True, []))


COMPLIANT = transparency.CTResult(compliant=True, verified=[])


def _validate_chain(chain, builder, strict=True, domain="example.com"):
    """validate_chain with a given trust data builder and no network access."""
    with mock.patch.object(PathBuilder, "mozilla", return_value=builder), \
            mock.patch.object(cv, "_check_dnssec"), \
            mock.patch.object(revocation, "check_leaf_revocation", return_value=True), \
            mock.patch.object(transparency, "check_transparency", return_value=COMPLIANT), \
            mock.patch("src.validation.chain_validator._ip_address", return_value="192.0.2.1"), \
            mock.patch.object(cv, "datetime") as fake_datetime:
        fake_datetime.now.return_value = NOW
        return ChainValidator.validate_chain(domain, chain, [], True, True, strict=strict)


if __name__ == "__main__":
    unittest.main()
