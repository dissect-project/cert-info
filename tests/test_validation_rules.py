"""
Tests for the validity rules of src/validation/certificate_validator.py,
src/chain/certificate_rules.py, src/validation/revocation.py and
src/validation/chain_validator.py: issuer rights, hostname matching, leaf
purpose, supported extensions and algorithms, revocation (CRL, OCSP and
stapled OCSP), OCSP Must-Staple, and chains Firefox would reject.
Network access, DNS and dig are mocked; the tests run offline.
"""

import ipaddress
import socket
import subprocess
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from src.chain import certificate_rules as rules
from src.fetch.network import FetchError, fetch
from src.validation import certificate_validator as cv
from src.validation import revocation, transparency
from src.validation.certificate_fields import CertificateFields
from src.validation.certificate_validator import CertificateValidator, LEAF, INTERMEDIATE
from src.validation.chain_validator import FIREFOX_REJECTS, ChainValidator, _ip_address

NOW = datetime.now(timezone.utc)
KEYS = {name: ec.generate_private_key(ec.SECP256R1()) for name in ("root", "ca", "leaf", "other")}


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, key, issuer, issuer_key, ca=False, path_length=None, key_usage=None,
          eku=None, san=None, crl=None, ocsp_url=None, days=90, basic_constraints=True,
          extensions=(), algorithm=None, expired=False):
    start = NOW - timedelta(days=days + 1) if expired else NOW - timedelta(days=1)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject)).issuer_name(_name(issuer))
        .public_key(KEYS[key].public_key() if isinstance(key, str) else key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + timedelta(days=days))
    )
    if basic_constraints:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
    if key_usage is not None:
        flags = dict.fromkeys(["digital_signature", "content_commitment", "key_encipherment",
                               "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign",
                               "encipher_only", "decipher_only"], False)
        flags.update(key_usage)
        builder = builder.add_extension(x509.KeyUsage(**flags), critical=True)
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if san is not None:
        names = [n if isinstance(n, x509.GeneralName) else x509.DNSName(n) for n in san]
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    if crl is not None:
        builder = builder.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
            [x509.UniformResourceIdentifier(crl)], None, None, None)]), critical=False)
    if ocsp_url is not None:
        builder = builder.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(
            x509.AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(ocsp_url))]),
            critical=False)
    for value, critical in extensions:
        builder = builder.add_extension(value, critical=critical)
    return builder.sign(KEYS[issuer_key], algorithm or hashes.SHA256())


CA = _cert("CA", "ca", "CA", "ca", ca=True)


def _validate(cert, issuer, cert_id=LEAF, position=0, domain="example.com", stapled_ocsp=None):
    """Validate without DNSSEC or revocation lookups."""
    with mock.patch.object(cv, "_check_dnssec"), \
            mock.patch.object(revocation, "check_leaf_revocation", return_value=True):
        return CertificateValidator.validate(domain, cert, issuer, cert_id, position,
                                             stapled_ocsp=stapled_ocsp)


class TestIssuerRights(unittest.TestCase):

    def test_leaf_issuer_must_be_ca(self):
        """The intermediate above the leaf used to be checked by nobody."""
        not_ca = _cert("CA", "ca", "CA", "ca", ca=False)
        leaf = _cert("example.com", "leaf", "CA", "ca", san=["example.com"])
        valid, issues, _ = _validate(leaf, not_ca)
        self.assertFalse(valid)
        self.assertIn(cv.NOT_VALID_CA, issues)

    def test_issuer_without_basic_constraints(self):
        no_bc = _cert("CA", "ca", "CA", "ca", basic_constraints=False)
        leaf = _cert("example.com", "leaf", "CA", "ca", san=["example.com"])
        self.assertIn(cv.NO_CA_INFO, _validate(leaf, no_bc)[1])

    def test_issuer_key_usage(self):
        issuer = _cert("CA", "ca", "CA", "ca", ca=True, key_usage={"digital_signature": True})
        leaf = _cert("example.com", "leaf", "CA", "ca", san=["example.com"])
        valid, issues, _ = _validate(leaf, issuer)
        self.assertFalse(valid)
        self.assertIn(cv.ISSUER_KEY_USAGE, issues)

    def test_issuer_extended_key_usage(self):
        issuer = _cert("CA", "ca", "CA", "ca", ca=True, eku=[ExtendedKeyUsageOID.CLIENT_AUTH])
        leaf = _cert("example.com", "leaf", "CA", "ca", san=["example.com"])
        valid, issues, _ = _validate(leaf, issuer)
        self.assertFalse(valid)
        self.assertIn(cv.ISSUER_EKU, issues)

    def test_any_extended_key_usage_is_not_enough(self):
        """Firefox ignores anyExtendedKeyUsage: the issuer needs serverAuth."""
        issuer = _cert("CA", "ca", "CA", "ca", ca=True, eku=[ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE])
        leaf = _cert("example.com", "leaf", "CA", "ca", san=["example.com"])
        self.assertIn(cv.ISSUER_EKU, _validate(leaf, issuer)[1])

    def test_path_length(self):
        """An issuer with pathLen 0 may not have an intermediate below it."""
        root = _cert("Root", "root", "Root", "root", ca=True, path_length=0)
        intermediate = _cert("CA", "ca", "Root", "root", ca=True)
        valid, issues, _ = _validate(intermediate, root, INTERMEDIATE, position=1)
        self.assertFalse(valid)
        self.assertIn(cv.ISSUER_PATH_LENGTH, issues)
        leaf = _cert("example.com", "leaf", "Root", "root", san=["example.com"])
        self.assertNotIn(cv.ISSUER_PATH_LENGTH, _validate(leaf, root)[1])

    def test_valid_leaf(self):
        leaf = _cert("example.com", "leaf", "CA", "ca", san=["example.com"],
                     eku=[ExtendedKeyUsageOID.SERVER_AUTH])
        self.assertEqual(_validate(leaf, CA)[:2], (True, []))


class TestLeafChecks(unittest.TestCase):

    def test_leaf_must_allow_server_auth(self):
        leaf = _cert("example.com", "leaf", "CA", "ca", san=["example.com"],
                     eku=[ExtendedKeyUsageOID.CLIENT_AUTH])
        valid, issues, _ = _validate(leaf, CA)
        self.assertFalse(valid)
        self.assertIn(cv.NOT_SERVER_AUTH, issues)

    def test_cn_is_ignored_when_san_present(self):
        """A matching CN used to be accepted even if no SAN entry matched."""
        leaf = _cert("evil.com", "leaf", "CA", "ca", san=["other.com"])
        valid, issues, _ = _validate(leaf, CA, domain="evil.com")
        self.assertFalse(valid)
        self.assertIn(cv.HOSTNAME_MISMATCH, issues)

    def test_cn_is_never_used(self):
        """Firefox only matches Subject Alternative Names, never the CN."""
        leaf = _cert("example.com", "leaf", "CA", "ca")
        valid, issues, _ = _validate(leaf, CA)
        self.assertFalse(valid)
        self.assertIn(cv.HOSTNAME_MISMATCH, issues)

    def test_wildcard_matches_one_label(self):
        """*.example.com used to match a.b.example.com."""
        self.assertEqual(cv._matches("*.example.com", "www.example.com"), (True, True))
        self.assertEqual(cv._matches("*.example.com", "a.b.example.com"), (False, False))
        self.assertEqual(cv._matches("*.example.com", "example.com"), (False, False))
        self.assertEqual(cv._matches("Example.COM", "example.com"), (True, False))
        self.assertEqual(cv._matches("example.com", "example.com."), (True, False))

    def test_wildcard_needs_two_labels_after_it(self):
        self.assertEqual(cv._matches("*.com", "example.com"), (False, False))
        self.assertEqual(cv._matches("*.co.uk", "example.co.uk"), (True, True))

    def test_only_whole_label_wildcards(self):
        self.assertEqual(cv._matches("w*.example.com", "www.example.com"), (False, False))
        self.assertEqual(cv._matches("*.*.example.com", "a.b.example.com"), (False, False))

    def test_invalid_san_name_stops_matching(self):
        """mozilla::pkix stops at an invalid DNS name in the SAN."""
        leaf = _cert("example.com", "leaf", "CA", "ca", san=["bad name.com", "example.com"])
        self.assertIn(cv.HOSTNAME_MISMATCH, _validate(leaf, CA)[1])
        leaf = _cert("example.com", "leaf", "CA", "ca", san=["example.com", "bad name.com"])
        self.assertNotIn(cv.HOSTNAME_MISMATCH, _validate(leaf, CA)[1])

    def test_ip_address_matches_ip_san_only(self):
        leaf = _cert("192.0.2.1", "leaf", "CA", "ca",
                     san=[x509.IPAddress(ipaddress.ip_address("192.0.2.1")), "example.com"])
        self.assertNotIn(cv.HOSTNAME_MISMATCH, _validate(leaf, CA, domain="192.0.2.1")[1])
        self.assertIn(cv.HOSTNAME_MISMATCH, _validate(leaf, CA, domain="192.0.2.2")[1])

    def test_any_extended_key_usage_leaf_is_rejected(self):
        leaf = _cert("example.com", "leaf", "CA", "ca", san=["example.com"],
                     eku=[ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE])
        self.assertIn(cv.NOT_SERVER_AUTH, _validate(leaf, CA)[1])

    def test_ca_certificate_as_leaf_is_rejected(self):
        leaf = _cert("example.com", "leaf", "CA", "ca", ca=True, san=["example.com"])
        valid, issues, _ = _validate(leaf, CA)
        self.assertFalse(valid)
        self.assertIn(rules.LEAF_IS_CA, issues)

    def test_ocsp_signing_leaf_is_rejected(self):
        leaf = _cert("example.com", "leaf", "CA", "ca", san=["example.com"],
                     eku=[ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.OCSP_SIGNING])
        self.assertIn(rules.LEAF_OCSP_SIGNING, _validate(leaf, CA)[1])

    def test_ca_certificates_are_not_hostname_checked(self):
        _, issues, warnings = _validate(CA, CA, cv.ROOT)
        self.assertNotIn(cv.HOSTNAME_MISMATCH, issues)
        self.assertNotIn(cv.NO_COMMON_NAME, warnings)


class TestAlgorithms(unittest.TestCase):
    """Firefox's algorithm rules decide validity; NIST statuses are only reported."""

    def leaf(self, key, algorithm=None):
        return _cert("example.com", key, "CA", "ca", san=["example.com"], algorithm=algorithm)

    def test_rsa_1024_is_accepted_like_firefox(self):
        valid, issues, _ = _validate(self.leaf(rsa.generate_private_key(65537, 1024)), CA)
        self.assertTrue(valid, issues)
        self.assertIn("Key " + cv.NIST_DISALLOWED, issues)

    def test_rsa_key_size_minimums(self):
        """1024 bits is Firefox's minimum; EV and its first ordinary attempt need 2048."""
        leaf = self.leaf(rsa.generate_private_key(65537, 1024))
        self.assertEqual(rules.key_problems(leaf), [])
        self.assertEqual(rules.key_problems(leaf, rules.MIN_RSA_BITS), [rules.RSA_KEY_TOO_SMALL.format(bits=2048)])

    def test_unsupported_curve_is_rejected(self):
        valid, issues, _ = _validate(self.leaf(ec.generate_private_key(ec.SECP256K1())), CA)
        self.assertFalse(valid)
        self.assertIn(rules.UNSUPPORTED_CURVE, issues)

    def test_eddsa_key_is_rejected(self):
        valid, issues, _ = _validate(self.leaf(ed25519.Ed25519PrivateKey.generate()), CA)
        self.assertFalse(valid)
        self.assertIn(rules.UNSUPPORTED_KEY, issues)

    def test_sha224_signature_is_rejected(self):
        """NIST only deprecates SHA-224, but Firefox does not support it."""
        valid, issues, _ = _validate(self.leaf("leaf", hashes.SHA224()), CA)
        self.assertFalse(valid)
        self.assertIn(rules.UNSUPPORTED_SIGNATURE, issues)
        self.assertIn("Hash " + cv.NIST_DEPRECATED, issues)

    def test_rsa_pss_needs_the_standard_parameters(self):
        """Firefox only accepts RSA-PSS with MGF-1 on the same hash and a salt as long as the hash."""
        rsa_ca_key = rsa.generate_private_key(65537, 2048)

        def pss_cert(algorithm, mgf_hash, salt):
            return (x509.CertificateBuilder().subject_name(_name("example.com")).issuer_name(_name("CA"))
                    .public_key(KEYS["leaf"].public_key()).serial_number(1)
                    .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=30))
                    .sign(rsa_ca_key, algorithm, rsa_padding=padding.PSS(padding.MGF1(mgf_hash), salt)))
        self.assertEqual(rules.signature_problems(pss_cert(hashes.SHA256(), hashes.SHA256(), 32)), [])
        self.assertEqual(rules.signature_problems(pss_cert(hashes.SHA384(), hashes.SHA384(), 48)), [])
        for algorithm, mgf_hash, salt in ((hashes.SHA256(), hashes.SHA256(), 20),
                                          (hashes.SHA256(), hashes.SHA384(), 32)):
            with self.subTest(salt=salt, mgf=mgf_hash.name):
                self.assertEqual(rules.signature_problems(pss_cert(algorithm, mgf_hash, salt)),
                                 [rules.UNSUPPORTED_SIGNATURE])

    def test_signature_algorithm_must_match_inside_and_outside(self):
        leaf = self.leaf("leaf")
        ecdsa_sha256 = bytes.fromhex("06082a8648ce3d040302")
        ecdsa_sha384 = bytes.fromhex("06082a8648ce3d040303")
        der = leaf.public_bytes(serialization.Encoding.DER)
        # The first occurrence is the copy inside the signed part
        tampered = x509.load_der_x509_certificate(der.replace(ecdsa_sha256, ecdsa_sha384, 1))
        self.assertEqual(rules.signature_problems(tampered), [rules.SIGNATURE_ALGORITHM_MISMATCH])

    def test_supported_signatures(self):
        for algorithm in (hashes.SHA256(), hashes.SHA384(), hashes.SHA512()):
            with self.subTest(algorithm=algorithm.name):
                self.assertEqual(rules.signature_problems(self.leaf("leaf", algorithm)), [])


class TestExtensions(unittest.TestCase):

    def test_unknown_critical_extension_is_rejected(self):
        unknown = x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4"), b"\x05\x00")
        leaf = _cert("example.com", "leaf", "CA", "ca", san=["example.com"], extensions=[(unknown, True)])
        valid, issues, _ = _validate(leaf, CA)
        self.assertFalse(valid)
        self.assertIn(rules.UNKNOWN_CRITICAL_EXTENSION, issues)
        not_critical = _cert("example.com", "leaf", "CA", "ca", san=["example.com"], extensions=[(unknown, False)])
        self.assertTrue(_validate(not_critical, CA)[0])

    def test_critical_key_identifiers_are_rejected(self):
        """mozilla::pkix ignores key identifiers, so it does not understand them as critical."""
        ski = x509.SubjectKeyIdentifier.from_public_key(KEYS["leaf"].public_key())
        leaf = _cert("example.com", "leaf", "CA", "ca", san=["example.com"], extensions=[(ski, True)])
        self.assertIn(rules.UNKNOWN_CRITICAL_EXTENSION, _validate(leaf, CA)[1])

    def test_duplicate_extensions_do_not_crash(self):
        """A certificate cryptography cannot parse the extensions of used to cause an HTTP 500."""
        first = x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4"), b"\x05\x00")
        second = x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.5"), b"\x05\x00")
        cert = _cert("example.com", "leaf", "CA", "ca", san=["example.com"],
                     extensions=[(first, False), (second, False)])
        der = cert.public_bytes(serialization.Encoding.DER).replace(
            b"\x06\x03\x2a\x03\x05", b"\x06\x03\x2a\x03\x04")
        duplicate = x509.load_der_x509_certificate(der)
        with self.assertRaises(x509.DuplicateExtension):
            duplicate.extensions
        valid, issues, _ = _validate(duplicate, CA)
        self.assertFalse(valid)
        self.assertIn(rules.MALFORMED_EXTENSIONS, issues)
        self.assertIn("subject", CertificateFields.decode(duplicate))


def _crl(revoked_serials, signer="ca", issuer="CA", next_update=None, extensions=()):
    builder = (x509.CertificateRevocationListBuilder().issuer_name(_name(issuer))
               .last_update(NOW - timedelta(days=10)).next_update(next_update or NOW + timedelta(days=1)))
    for value in extensions:
        builder = builder.add_extension(value, critical=True)
    for serial in revoked_serials:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(NOW).build())
    return builder.sign(KEYS[signer], hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _ocsp_response(cert, status, signer="ca", responder=None, this_update=None, next_update=None,
                   certificates=None):
    responder = responder or CA
    this_update = this_update or NOW - timedelta(hours=1)
    builder = ocsp.OCSPResponseBuilder().add_response(
        cert=cert, issuer=CA, algorithm=hashes.SHA1(), cert_status=status,
        this_update=this_update, next_update=next_update or this_update + timedelta(days=1),
        revocation_time=NOW if status == ocsp.OCSPCertStatus.REVOKED else None,
        revocation_reason=None).responder_id(ocsp.OCSPResponderEncoding.HASH, responder)
    if certificates:
        builder = builder.certificates(certificates)
    return builder.sign(KEYS[signer], hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _ocsp(cert, status, signer="ca", responder=None, requested_hashes=None):
    def respond(url, data=None, content_type=None):
        request = ocsp.load_der_ocsp_request(data)
        if requested_hashes is not None:
            requested_hashes.append(request.hash_algorithm.name)
        return _ocsp_response(cert, status, signer, responder)
    return respond


def _no_fetch(url, **kw):
    raise AssertionError(f"unexpected fetch of {url}")


class TestRevocation(unittest.TestCase):
    """Leaf revocation as Firefox checks it (see src/validation/revocation.py)."""

    def setUp(self):
        revocation.clear_caches()

    def check(self, cert, fetcher, stapled=None):
        issues, warnings = [], []
        with mock.patch.object(revocation, "fetch", side_effect=fetcher):
            result = revocation.check_leaf_revocation(cert, CA, issues, warnings, stapled)
        return result, issues, warnings

    def test_crl_revoked(self):
        cert = _cert("example.com", "leaf", "CA", "ca", crl="http://crl.example/ca.crl")
        result = self.check(cert, lambda url, **kw: _crl([cert.serial_number]))
        self.assertEqual(result[:2], (False, [revocation.CRL_REVOKED]))

    def test_crl_is_final(self):
        """Like CRLite, a usable CRL decides: OCSP and the stapled response are not consulted."""
        cert = _cert("example.com", "leaf", "CA", "ca", crl="http://crl.example/ca.crl",
                     ocsp_url="http://ocsp.example")
        stapled = _ocsp_response(cert, ocsp.OCSPCertStatus.REVOKED)

        def crl_only(url, **kw):
            self.assertIn("crl", url)
            return _crl([12345])
        self.assertEqual(self.check(cert, crl_only, stapled), (True, [], []))

    def test_forged_crl_is_ignored(self):
        """A CRL not signed by the issuer used to be trusted."""
        cert = _cert("example.com", "leaf", "CA", "ca", crl="http://crl.example/ca.crl")
        valid, issues, warnings = self.check(cert, lambda url, **kw: _crl([cert.serial_number], signer="other"))
        self.assertTrue(valid)
        self.assertEqual(issues, [])
        self.assertIn("CRL signature could not be verified", warnings[0])

    def test_ocsp_uses_sha1_and_detects_revocation(self):
        """Many responders (DigiCert, Microsoft, Amazon) reject SHA-256 requests."""
        cert = _cert("example.com", "leaf", "CA", "ca", ocsp_url="http://ocsp.example")
        hashes_used = []
        valid, issues, _ = self.check(cert, _ocsp(cert, ocsp.OCSPCertStatus.REVOKED,
                                                  requested_hashes=hashes_used))
        self.assertEqual(hashes_used, ["sha1"])
        self.assertEqual((valid, issues), (False, [revocation.OCSP_REVOKED]))

    def test_ocsp_good(self):
        cert = _cert("example.com", "leaf", "CA", "ca", ocsp_url="http://ocsp.example")
        self.assertEqual(self.check(cert, _ocsp(cert, ocsp.OCSPCertStatus.GOOD)), (True, [], []))

    def test_forged_ocsp_response_is_ignored(self):
        cert = _cert("example.com", "leaf", "CA", "ca", ocsp_url="http://ocsp.example")
        impostor = _cert("CA", "other", "CA", "other", ca=True)  # same name, wrong key
        valid, issues, warnings = self.check(cert, _ocsp(cert, ocsp.OCSPCertStatus.REVOKED,
                                                         signer="other", responder=impostor))
        self.assertTrue(valid)
        self.assertIn(revocation.INVALID_SIGNING_CERT, warnings[0])

    def test_unsuccessful_ocsp_answer_is_reported(self):
        """Unsuccessful answers used to be ignored silently."""
        cert = _cert("example.com", "leaf", "CA", "ca", ocsp_url="http://ocsp.example")
        unauthorized = ocsp.OCSPResponseBuilder.build_unsuccessful(
            ocsp.OCSPResponseStatus.UNAUTHORIZED).public_bytes(serialization.Encoding.DER)
        _, _, warnings = self.check(cert, lambda url, **kw: unauthorized)
        self.assertEqual(warnings, ["Failed to check OCSP at http://ocsp.example: responder answered UNAUTHORIZED"])

    def test_fetch_errors_do_not_leak_details(self):
        cert = _cert("example.com", "leaf", "CA", "ca", crl="http://10.0.0.1/ca.crl")

        def blocked(url, **kw):
            raise FetchError("address not allowed")
        _, _, warnings = self.check(cert, blocked)
        self.assertEqual(warnings, ["Failed to check CRL at http://10.0.0.1/ca.crl: address not allowed"])

    def test_missing_revocation_info_is_only_a_warning(self):
        """Firefox does not require CRL or OCSP information."""
        cert = _cert("example.com", "leaf", "CA", "ca", days=90)
        self.assertEqual(self.check(cert, _no_fetch), (True, [], [revocation.NO_REVOCATION_INFO]))

    def test_short_lived_certificate_is_not_queried(self):
        short = _cert("example.com", "leaf", "CA", "ca", days=9, ocsp_url="http://ocsp.example")
        self.assertEqual(self.check(short, _no_fetch), (True, [], []))

    def test_expired_certificate_is_not_checked(self):
        expired = _cert("example.com", "leaf", "CA", "ca", expired=True, crl="http://crl.example/ca.crl")
        self.assertEqual(self.check(expired, _no_fetch), (True, [], []))

    def test_stapled_good_response(self):
        cert = _cert("example.com", "leaf", "CA", "ca", ocsp_url="http://ocsp.example")
        stapled = _ocsp_response(cert, ocsp.OCSPCertStatus.GOOD)
        self.assertEqual(self.check(cert, _no_fetch, stapled), (True, [], []))

    def test_stapled_revoked_response(self):
        cert = _cert("example.com", "leaf", "CA", "ca")
        stapled = _ocsp_response(cert, ocsp.OCSPCertStatus.REVOKED)
        self.assertEqual(self.check(cert, _no_fetch, stapled)[:2], (False, [revocation.STAPLED_OCSP_REVOKED]))

    def test_stapled_unknown_or_forged_response_is_rejected(self):
        cert = _cert("example.com", "leaf", "CA", "ca")
        good = _ocsp_response(cert, ocsp.OCSPCertStatus.GOOD)
        corrupted = good[:-1] + bytes([good[-1] ^ 1])  # the signature is the last field
        for stapled, reason in (
                (_ocsp_response(cert, ocsp.OCSPCertStatus.UNKNOWN), revocation.UNKNOWN),
                (corrupted, revocation.BAD_SIGNATURE),
                (_ocsp_response(cert, ocsp.OCSPCertStatus.GOOD, this_update=NOW + timedelta(days=2)),
                 revocation.FUTURE),
                (b"not an OCSP response", revocation.MALFORMED)):
            with self.subTest(reason=reason):
                self.assertEqual(self.check(cert, _no_fetch, stapled)[:2],
                                 (False, [revocation.STAPLED_OCSP_INVALID.format(reason=reason)]))

    def test_expired_stapled_response_is_ignored_whatever_it_says(self):
        """Firefox ignores an expired stapled response, even one saying 'revoked' or 'unknown'."""
        cert = _cert("example.com", "leaf", "CA", "ca")
        for status in (ocsp.OCSPCertStatus.REVOKED, ocsp.OCSPCertStatus.UNKNOWN):
            with self.subTest(status=status.name):
                stapled = _ocsp_response(cert, status, this_update=NOW - timedelta(days=5))
                self.assertEqual(self.check(cert, _no_fetch, stapled),
                                 (True, [], [revocation.STAPLED_OCSP_IGNORED.format(reason=revocation.OLD)]))

    def test_expired_revoked_response_from_the_network_counts(self):
        cert = _cert("example.com", "leaf", "CA", "ca")
        old = _ocsp_response(cert, ocsp.OCSPCertStatus.REVOKED, this_update=NOW - timedelta(days=5))
        self.assertEqual(revocation.evaluate_ocsp(old, cert, CA, NOW)[0], revocation.REVOKED)

    def test_tolerated_stapled_responses_are_ignored(self):
        """Firefox ignores expired responses and responses about another certificate."""
        cert = _cert("example.com", "leaf", "CA", "ca")
        other = _cert("other.example", "leaf", "CA", "ca")
        for stapled, reason in (
                (_ocsp_response(cert, ocsp.OCSPCertStatus.GOOD, this_update=NOW - timedelta(days=5)),
                 revocation.OLD),
                (_ocsp_response(other, ocsp.OCSPCertStatus.REVOKED), revocation.NOT_FOR_CERTIFICATE)):
            with self.subTest(reason=reason):
                self.assertEqual(self.check(cert, _no_fetch, stapled),
                                 (True, [], [revocation.STAPLED_OCSP_IGNORED.format(reason=reason)]))

    def crl_then_ocsp(self, cert, crl):
        """CRL at http://crl.example, OCSP answering 'revoked' at http://ocsp.example."""
        revoked = _ocsp(cert, ocsp.OCSPCertStatus.REVOKED)
        return lambda url, **kw: crl if "crl" in url else revoked(url, **kw)

    def test_expired_crl_does_not_prove_good_standing(self):
        """An expired CRL that does not list the certificate used to be final."""
        cert = _cert("example.com", "leaf", "CA", "ca", crl="http://crl.example/ca.crl",
                     ocsp_url="http://ocsp.example")
        stale = _crl([12345], next_update=NOW - timedelta(days=1))
        valid, issues, warnings = self.check(cert, self.crl_then_ocsp(cert, stale))
        self.assertEqual((valid, issues), (False, [revocation.OCSP_REVOKED]))
        self.assertIn("CRL has expired", warnings[0])

    def test_expired_crl_listing_the_certificate(self):
        """Revocation is permanent: an expired CRL that lists the certificate still counts."""
        cert = _cert("example.com", "leaf", "CA", "ca", crl="http://crl.example/ca.crl")
        stale = _crl([cert.serial_number], next_update=NOW - timedelta(days=1))
        self.assertEqual(self.check(cert, lambda url, **kw: stale)[:2], (False, [revocation.CRL_REVOKED]))

    def test_partial_crls_do_not_prove_good_standing(self):
        cert = _cert("example.com", "leaf", "CA", "ca", crl="http://crl.example/ca.crl",
                     ocsp_url="http://ocsp.example")
        point = dict(full_name=None, relative_name=None, only_contains_user_certs=False,
                     only_contains_ca_certs=False, only_some_reasons=None, indirect_crl=False,
                     only_contains_attribute_certs=False)
        for extension, reason in (
                (x509.IssuingDistributionPoint(**{**point, "only_contains_ca_certs": True}),
                 "CRL does not cover end-entity certificates"),
                (x509.IssuingDistributionPoint(**{**point, "only_some_reasons": frozenset(
                    [x509.ReasonFlags.key_compromise])}), "CRL only covers some revocation reasons"),
                (x509.DeltaCRLIndicator(1), "delta CRLs are not supported"),
                (x509.IssuingDistributionPoint(**{**point, "indirect_crl": True}),
                 "indirect CRLs are not supported")):
            with self.subTest(reason=reason):
                revocation.clear_caches()  # same URL, another CRL
                partial = _crl([12345], extensions=[extension])
                valid, issues, warnings = self.check(cert, self.crl_then_ocsp(cert, partial))
                self.assertEqual((valid, issues), (False, [revocation.OCSP_REVOKED]))
                self.assertIn(reason, warnings[0])

    def test_end_entity_crl_with_distribution_point_is_final(self):
        cert = _cert("example.com", "leaf", "CA", "ca", crl="http://crl.example/ca.crl",
                     ocsp_url="http://ocsp.example")
        point = x509.IssuingDistributionPoint(
            full_name=[x509.UniformResourceIdentifier("http://crl.example/ca.crl")], relative_name=None,
            only_contains_user_certs=True, only_contains_ca_certs=False, only_some_reasons=None,
            indirect_crl=False, only_contains_attribute_certs=False)
        complete = _crl([12345], extensions=[point])
        self.assertEqual(self.check(cert, self.crl_then_ocsp(cert, complete)), (True, [], []))

    def test_stapled_scts_only_when_the_response_was_used(self):
        """Firefox does not read the stapled response (or its SCTs) when CRLite decides."""
        cert = _cert("example.com", "leaf", "CA", "ca", crl="http://crl.example/ca.crl")
        good_with_scts = (revocation.GOOD, b"scts")
        with mock.patch.object(revocation, "evaluate_ocsp", return_value=good_with_scts), \
                mock.patch.object(revocation, "fetch", side_effect=lambda url, **kw: _crl([12345])):
            outcome = {}
            revocation.check_leaf_revocation(cert, CA, [], [], b"stapled", outcome=outcome)
            self.assertEqual(outcome, {})
        revocation.clear_caches()
        with mock.patch.object(revocation, "evaluate_ocsp", return_value=good_with_scts), \
                mock.patch.object(revocation, "fetch", side_effect=FetchError("download failed")):
            outcome = {}
            revocation.check_leaf_revocation(cert, CA, [], [], b"stapled", outcome=outcome)
            self.assertEqual(outcome, {"ocsp_scts": b"scts"})

    def test_delegated_responder_must_pass_firefox_checks(self):
        """A responder certificate Firefox would not accept (unsupported key, unknown critical extension)."""
        cert = _cert("example.com", "leaf", "CA", "ca")
        k1 = ec.generate_private_key(ec.SECP256K1())
        unknown = x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4"), b"\x05\x00")
        for responder, signer in (
                (_cert("Responder", k1, "CA", "ca", eku=[ExtendedKeyUsageOID.OCSP_SIGNING]), k1),
                (_cert("Responder", "other", "CA", "ca", eku=[ExtendedKeyUsageOID.OCSP_SIGNING],
                       extensions=[(unknown, True)]), KEYS["other"])):
            with self.subTest(responder=responder.public_key().__class__.__name__):
                stapled = (ocsp.OCSPResponseBuilder().add_response(
                    cert=cert, issuer=CA, algorithm=hashes.SHA1(), cert_status=ocsp.OCSPCertStatus.REVOKED,
                    this_update=NOW - timedelta(hours=1), next_update=NOW + timedelta(days=1),
                    revocation_time=NOW, revocation_reason=None)
                    .responder_id(ocsp.OCSPResponderEncoding.HASH, responder).certificates([responder])
                    .sign(signer, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
                self.assertEqual(revocation.evaluate_ocsp(stapled, cert, CA, NOW)[0],
                                 revocation.INVALID_SIGNING_CERT)

    def test_crls_are_downloaded_once(self):
        cert = _cert("example.com", "leaf", "CA", "ca", crl="http://crl.example/ca.crl")
        downloads = []

        def counting(url, **kw):
            downloads.append(url)
            return _crl([12345])
        for _ in range(3):
            self.assertEqual(self.check(cert, counting), (True, [], []))
        self.assertEqual(len(downloads), 1)

    def test_cached_crl_expires(self):
        """A cached CRL is reused until its next update, but at most CACHE_MAX_AGE."""
        url = "http://crl.example/ca.crl"
        with mock.patch.object(revocation, "fetch", side_effect=lambda u, **kw: _crl([1])) as fetch_mock:
            revocation._download_crl(url, NOW)
            revocation._download_crl(url, NOW + revocation.CACHE_MAX_AGE - timedelta(seconds=1))
            self.assertEqual(fetch_mock.call_count, 1)
            revocation._download_crl(url, NOW + revocation.CACHE_MAX_AGE)
            self.assertEqual(fetch_mock.call_count, 2)
        revocation.clear_caches()
        soon = NOW + timedelta(minutes=5)   # next update before CACHE_MAX_AGE
        with mock.patch.object(revocation, "fetch", side_effect=lambda u, **kw: _crl([1], next_update=soon)) as m:
            revocation._download_crl(url, NOW)
            revocation._download_crl(url, soon)
            self.assertEqual(m.call_count, 2)

    def test_failures_and_expired_crls_are_not_cached(self):
        cert = _cert("example.com", "leaf", "CA", "ca", crl="http://crl.example/ca.crl")
        calls = []

        def failing(url, **kw):
            calls.append(url)
            raise FetchError("download failed")
        self.check(cert, failing)
        self.check(cert, failing)
        self.assertEqual(len(calls), 2)
        stale = _crl([12345], next_update=NOW - timedelta(days=1))
        with mock.patch.object(revocation, "fetch", return_value=stale) as fetch_mock:
            revocation._download_crl("http://crl.example/stale.crl", NOW)
            revocation._download_crl("http://crl.example/stale.crl", NOW)
            self.assertEqual(fetch_mock.call_count, 2)

    def test_ocsp_responses_are_reused_for_the_same_certificate(self):
        cert = _cert("example.com", "leaf", "CA", "ca", ocsp_url="http://ocsp.example")
        other = _cert("other.example", "leaf", "CA", "ca", ocsp_url="http://ocsp.example")
        calls = []

        def counting(url, data=None, content_type=None):
            calls.append(data)
            request = ocsp.load_der_ocsp_request(data)
            target = cert if request.serial_number == cert.serial_number else other
            return _ocsp(target, ocsp.OCSPCertStatus.GOOD)(url, data, content_type)
        for target in (cert, cert, other):
            self.assertTrue(self.check(target, counting)[0])
        self.assertEqual(len(calls), 2)

    def test_unsuccessful_ocsp_answers_are_not_cached(self):
        try_later = ocsp.OCSPResponseBuilder.build_unsuccessful(
            ocsp.OCSPResponseStatus.TRY_LATER).public_bytes(serialization.Encoding.DER)
        with mock.patch.object(revocation, "fetch", return_value=try_later) as fetch_mock:
            revocation._download_ocsp("http://ocsp.example", b"request", NOW)
            revocation._download_ocsp("http://ocsp.example", b"request", NOW)
            self.assertEqual(fetch_mock.call_count, 2)

    def test_delegated_responder(self):
        """A responder certificate issued by the CA for OCSP signing may sign responses."""
        cert = _cert("example.com", "leaf", "CA", "ca")
        responder = _cert("Responder", "other", "CA", "ca", eku=[ExtendedKeyUsageOID.OCSP_SIGNING])
        stapled = _ocsp_response(cert, ocsp.OCSPCertStatus.REVOKED, signer="other", responder=responder,
                                 certificates=[responder])
        self.assertEqual(self.check(cert, _no_fetch, stapled)[:2], (False, [revocation.STAPLED_OCSP_REVOKED]))
        not_authorised = _cert("Responder", "other", "CA", "ca")
        stapled = _ocsp_response(cert, ocsp.OCSPCertStatus.REVOKED, signer="other",
                                 responder=not_authorised, certificates=[not_authorised])
        self.assertTrue(self.check(cert, _no_fetch, stapled)[0])

    def test_response_with_several_certificates(self):
        """Accessing serial_number on such a response raised ValueError (HTTP 500)."""
        cert = _cert("example.com", "leaf", "CA", "ca")
        singles = []
        for serial, status in ((12345, ocsp.OCSPCertStatus.GOOD), (cert.serial_number, ocsp.OCSPCertStatus.REVOKED)):
            single = mock.Mock(serial_number=serial, hash_algorithm=hashes.SHA1(), certificate_status=status,
                               this_update_utc=NOW - timedelta(hours=1), next_update_utc=NOW + timedelta(days=1))
            real = ocsp.load_der_ocsp_response(_ocsp_response(cert, status))
            single.issuer_name_hash, single.issuer_key_hash = real.issuer_name_hash, real.issuer_key_hash
            singles.append(single)
        response = mock.Mock(response_status=ocsp.OCSPResponseStatus.SUCCESSFUL, responses=singles)
        type(response).serial_number = mock.PropertyMock(side_effect=ValueError("2 SINGLERESP structures"))
        with mock.patch.object(revocation, "load_der_ocsp_response", return_value=response), \
                mock.patch.object(revocation, "_ocsp_signature_status", return_value=None):
            self.assertEqual(revocation.evaluate_ocsp(b"", cert, CA, NOW), (revocation.REVOKED, None))

    def test_cert_id_key_hash_matches_cryptography(self):
        """The issuer key hash is computed over the subjectPublicKey bits."""
        for key in (KEYS["ca"], rsa.generate_private_key(65537, 2048)):
            issuer = (
                x509.CertificateBuilder().subject_name(_name("CA")).issuer_name(_name("CA"))
                .public_key(key.public_key()).serial_number(1)
                .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=1))
                .sign(key, hashes.SHA256()))
            leaf = (x509.CertificateBuilder().subject_name(_name("leaf")).issuer_name(_name("CA"))
                    .public_key(KEYS["leaf"].public_key()).serial_number(2)
                    .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=1))
                    .sign(key, hashes.SHA256()))
            request = ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, hashes.SHA256()).build()
            digest = hashes.Hash(hashes.SHA256())
            digest.update(revocation._public_key_bits(issuer))
            self.assertEqual(digest.finalize(), request.issuer_key_hash)

    def test_intermediates_are_not_checked_online(self):
        """Firefox only uses OneCRL for CA certificates."""
        intermediate = _cert("Sub CA", "other", "CA", "ca", ca=True, crl="http://crl.example/ca.crl")
        with mock.patch.object(cv, "_check_dnssec"), mock.patch.object(revocation, "fetch", side_effect=_no_fetch):
            valid, issues, _ = CertificateValidator.validate("example.com", intermediate, CA, INTERMEDIATE, 1)
        self.assertTrue(valid, issues)


class TestMustStaple(unittest.TestCase):
    MUST_STAPLE = (x509.TLSFeature([x509.TLSFeatureType.status_request]), False)

    def test_missing_stapled_response(self):
        leaf = _cert("example.com", "leaf", "CA", "ca", san=["example.com"], extensions=[self.MUST_STAPLE])
        valid, issues, _ = _validate(leaf, CA)
        self.assertFalse(valid)
        self.assertIn(revocation.MUST_STAPLE_MISSING, issues)

    def test_stapled_response_present(self):
        leaf = _cert("example.com", "leaf", "CA", "ca", san=["example.com"], extensions=[self.MUST_STAPLE])
        stapled = _ocsp_response(leaf, ocsp.OCSPCertStatus.GOOD)
        self.assertNotIn(revocation.MUST_STAPLE_MISSING, _validate(leaf, CA, stapled_ocsp=stapled)[1])


class TestSafeFetch(unittest.TestCase):
    """URLs from certificates may only reach public addresses over http."""

    def test_internal_addresses_are_refused(self):
        for url in ("http://127.0.0.1/", "http://localhost/", "http://169.254.169.254/latest/",
                    "http://10.1.2.3/crl", "http://[::1]/", "http://192.168.1.1:8080/"):
            with self.subTest(url=url):
                with self.assertRaises(FetchError) as error:
                    fetch(url)
                self.assertIn(str(error.exception), ("address not allowed", "host not found"))

    def test_only_http_is_fetched(self):
        for url in ("https://example.com/", "file:///etc/passwd", "ftp://example.com/x"):
            with self.subTest(url=url), self.assertRaises(FetchError):
                fetch(url)

    def test_dns_answer_with_private_address_is_refused(self):
        private = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 80))]
        with mock.patch("socket.getaddrinfo", return_value=private):
            with self.assertRaises(FetchError):
                fetch("http://crl.attacker.example/")


class TestChainStatus(unittest.TestCase):

    def test_chain_firefox_would_reject_is_invalid(self):
        leaf = _cert("example.com", "leaf", "CA", "ca", san=["example.com"])
        chain = [{"id": LEAF, "origin": "Server", "cert": leaf},
                 {"id": cv.ROOT, "origin": "Mozilla CA Bundle", "cert": CA}]
        with mock.patch.object(cv, "_check_dnssec"), \
                mock.patch.object(revocation, "check_leaf_revocation", return_value=True), \
                mock.patch.object(transparency, "check_transparency",
                                  return_value=transparency.CTResult(True, [])), \
                mock.patch("src.validation.chain_validator._ip_address", return_value="192.0.2.1"):
            accepted = ChainValidator.validate_chain("example.com", chain, [], True, False, strict=True)
            rejected = ChainValidator.validate_chain("example.com", chain, [], True, False, strict=False)
        self.assertEqual(accepted["status"], "valid")
        self.assertEqual(rejected["status"], "invalid")
        self.assertIn(FIREFOX_REJECTS, rejected["analysis"])

    def test_ipv6_only_domain(self):
        """gethostbyname used to raise for IPv6-only domains (HTTP 500)."""
        ipv6 = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 443, 0, 0))]
        with mock.patch("socket.getaddrinfo", return_value=ipv6):
            self.assertEqual(_ip_address("ipv6.example"), "2001:db8::1")
        with mock.patch("socket.getaddrinfo", side_effect=socket.gaierror):
            self.assertIsNone(_ip_address("missing.example"))


class TestDnssec(unittest.TestCase):

    def run_dig(self, stdout, returncode=0):
        warnings = []
        result = subprocess.CompletedProcess([], returncode, stdout=stdout, stderr="")
        with mock.patch("subprocess.run", return_value=result):
            cv._check_dnssec("example.com", warnings)
        return warnings

    def test_validated(self):
        self.assertEqual(self.run_dig(";; flags: qr rd ra ad; QUERY: 1, ANSWER: 2"), [])

    def test_not_validated(self):
        self.assertEqual(self.run_dig(";; flags: qr rd ra; QUERY: 1, ANSWER: 2"), [cv.DNSSEC_FAILED])

    def test_result_computed_in_parallel_is_used(self):
        """analyze() starts the DNSSEC check early; validation must not run dig again."""
        leaf = _cert("example.com", "leaf", "CA", "ca", san=["example.com"])
        with mock.patch("subprocess.run", side_effect=AssertionError("dig run twice")), \
                mock.patch.object(revocation, "check_leaf_revocation", return_value=True):
            _, _, warnings = CertificateValidator.validate("example.com", leaf, CA, LEAF,
                                                           dnssec_warnings=[cv.DNSSEC_FAILED])
        self.assertEqual(warnings[0], cv.DNSSEC_FAILED)

    def test_resolver_unreachable(self):
        """Used to report 'DNSSEC validation failed.' when dig could not reach 8.8.8.8."""
        self.assertEqual(self.run_dig(";; connection timed out; no servers could be reached", 9),
                         [cv.DNSSEC_UNAVAILABLE])


if __name__ == "__main__":
    unittest.main()
