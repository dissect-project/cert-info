"""
Tests for Certificate Transparency (src/validation/transparency.py) and for
reading the stapled OCSP response and SCTs from the TLS handshake
(src/fetch/tls.py). The CT logs and SCTs are generated, so the tests run
offline.
"""

import hashlib
import subprocess
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID

from src.fetch import tls
from src.trust.store import CTLog, CTLogList, TrustStore
from src.validation import transparency
from src.validation.chain_validator import CT_NOT_CHECKED, ChainValidator
from src.validation.certificate_validator import LEAF, ROOT

NOW = datetime.now(timezone.utc).replace(microsecond=0)
CA_KEY = ec.generate_private_key(ec.SECP256R1())
LEAF_KEY = ec.generate_private_key(ec.SECP256R1())


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


CA = (x509.CertificateBuilder().subject_name(_name("CA")).issuer_name(_name("CA"))
      .public_key(CA_KEY.public_key()).serial_number(1)
      .not_valid_before(NOW - timedelta(days=10)).not_valid_after(NOW + timedelta(days=3650))
      .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
      .sign(CA_KEY, hashes.SHA256()))


class Log:
    """A generated CT log."""

    def __init__(self, name, operator, admissible=True, tiled=False, retired=None):
        self.key = ec.generate_private_key(ec.SECP256R1())
        spki = self.key.public_key().public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)
        self.info = CTLog(name=name, log_id=hashlib.sha256(spki).digest(), admissible=admissible,
                          tiled=tiled, timestamp=retired or NOW - timedelta(days=1000),
                          operator_id=operator, key=spki)

    def sct(self, entry_type, entry, timestamp=None, leaf_index=None):
        """An encoded SCT for a log entry."""
        timestamp_ms = int((timestamp or NOW - timedelta(hours=1)).timestamp() * 1000)
        extensions = b""
        if leaf_index is not None:
            extensions = b"\x00" + (5).to_bytes(2, "big") + leaf_index.to_bytes(5, "big")
        signed = (b"\x00\x00" + timestamp_ms.to_bytes(8, "big") + entry_type.to_bytes(2, "big") + entry
                  + len(extensions).to_bytes(2, "big") + extensions)
        signature = self.key.sign(signed, ec.ECDSA(hashes.SHA256()))
        return (b"\x00" + self.info.log_id + timestamp_ms.to_bytes(8, "big")
                + len(extensions).to_bytes(2, "big") + extensions
                + b"\x04\x03" + len(signature).to_bytes(2, "big") + signature)


def _sct_list(scts):
    body = b"".join(len(s).to_bytes(2, "big") + s for s in scts)
    return len(body).to_bytes(2, "big") + body


def _leaf_builder(days):
    return (x509.CertificateBuilder().subject_name(_name("example.com")).issuer_name(_name("CA"))
            .public_key(LEAF_KEY.public_key()).serial_number(1234)
            .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW - timedelta(days=1) + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False))


def _leaf_with_embedded_scts(logs, days=90, **sct_args):
    """A leaf whose embedded SCTs are signed over its precertificate entry."""
    precert = _leaf_builder(days).sign(CA_KEY, hashes.SHA256())
    issuer_key_hash = hashlib.sha256(CA.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).digest()
    tbs = precert.tbs_certificate_bytes
    entry = issuer_key_hash + len(tbs).to_bytes(3, "big") + tbs
    sct_list = _sct_list([log.sct(1, entry, **sct_args) for log in logs])
    octet_string = b"\x04" + _der_length(len(sct_list)) + sct_list
    extension = x509.UnrecognizedExtension(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS, octet_string)
    leaf = _leaf_builder(days).add_extension(extension, critical=False).sign(CA_KEY, hashes.SHA256())
    assert leaf.tbs_precertificate_bytes == tbs
    return leaf


def _der_length(length):
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _x509_entry(leaf):
    der = leaf.public_bytes(serialization.Encoding.DER)
    return len(der).to_bytes(3, "big") + der


def _logs(*logs, expiration=NOW + timedelta(days=30)):
    return CTLogList({log.info.log_id: log.info for log in logs}, expiration)


GOOGLE_1, GOOGLE_2 = Log("Google 1", 0), Log("Google 2", 0)
CLOUDFLARE, DIGICERT = Log("Cloudflare", 1), Log("DigiCert", 2)


class TestEmbeddedSCTs(unittest.TestCase):

    def check(self, leaf, logs, **kwargs):
        return transparency.check_transparency(leaf, CA, logs, now=NOW, **kwargs)

    def test_two_operators_are_compliant(self):
        leaf = _leaf_with_embedded_scts([GOOGLE_1, CLOUDFLARE])
        result = self.check(leaf, _logs(GOOGLE_1, CLOUDFLARE))
        self.assertTrue(result.compliant, result.details())
        self.assertEqual(len(result.verified), 2)

    def test_one_sct_is_not_enough(self):
        leaf = _leaf_with_embedded_scts([GOOGLE_1])
        self.assertFalse(self.check(leaf, _logs(GOOGLE_1, CLOUDFLARE)).compliant)

    def test_same_operator_is_not_diverse(self):
        leaf = _leaf_with_embedded_scts([GOOGLE_1, GOOGLE_2])
        self.assertFalse(self.check(leaf, _logs(GOOGLE_1, GOOGLE_2)).compliant)

    def test_long_lived_certificates_need_three(self):
        two = _leaf_with_embedded_scts([GOOGLE_1, CLOUDFLARE], days=200)
        self.assertFalse(self.check(two, _logs(GOOGLE_1, CLOUDFLARE, DIGICERT)).compliant)
        three = _leaf_with_embedded_scts([GOOGLE_1, CLOUDFLARE, DIGICERT], days=200)
        self.assertTrue(self.check(three, _logs(GOOGLE_1, CLOUDFLARE, DIGICERT)).compliant)

    def test_unknown_log_does_not_count(self):
        leaf = _leaf_with_embedded_scts([GOOGLE_1, CLOUDFLARE])
        result = self.check(leaf, _logs(GOOGLE_1))
        self.assertFalse(result.compliant)
        self.assertEqual(result.unknown_log, 1)

    def test_bad_signature_does_not_count(self):
        leaf = _leaf_with_embedded_scts([GOOGLE_1, CLOUDFLARE])
        impostor = Log("Cloudflare", 1)
        impostor.info = CTLog(**{**CLOUDFLARE.info.__dict__, "key": impostor.info.key})
        result = self.check(leaf, _logs(GOOGLE_1, impostor))
        self.assertFalse(result.compliant)
        self.assertEqual(result.invalid, 1)

    def test_retired_log(self):
        """A retired log counts if it was retired after the certificate was issued."""
        retired_later = Log("Retired", 1, admissible=False, retired=NOW)
        leaf = _leaf_with_embedded_scts([GOOGLE_1, retired_later])
        self.assertTrue(self.check(leaf, _logs(GOOGLE_1, retired_later)).compliant)
        retired_before = Log("Retired", 1, admissible=False, retired=NOW - timedelta(days=2))
        leaf = _leaf_with_embedded_scts([GOOGLE_1, retired_before])
        self.assertFalse(self.check(leaf, _logs(GOOGLE_1, retired_before)).compliant)

    def test_retired_logs_alone_are_not_enough(self):
        retired = [Log(f"Retired {i}", i, admissible=False, retired=NOW) for i in (1, 2)]
        leaf = _leaf_with_embedded_scts(retired)
        self.assertFalse(self.check(leaf, _logs(*retired)).compliant)

    def test_tiled_logs_need_a_leaf_index(self):
        tiled = Log("Tiled", 1, tiled=True)
        without = _leaf_with_embedded_scts([GOOGLE_1, tiled])
        self.assertFalse(self.check(without, _logs(GOOGLE_1, tiled)).compliant)
        with_index = _leaf_with_embedded_scts([GOOGLE_1, tiled], leaf_index=42)
        self.assertTrue(self.check(with_index, _logs(GOOGLE_1, tiled)).compliant)

    def test_future_and_distrusted_timestamps_do_not_count(self):
        future = _leaf_with_embedded_scts([GOOGLE_1, CLOUDFLARE], timestamp=NOW + timedelta(hours=1))
        self.assertFalse(self.check(future, _logs(GOOGLE_1, CLOUDFLARE)).compliant)
        leaf = _leaf_with_embedded_scts([GOOGLE_1, CLOUDFLARE])
        self.assertFalse(self.check(leaf, _logs(GOOGLE_1, CLOUDFLARE),
                                    distrust_after=NOW - timedelta(days=1)).compliant)

    def test_not_enforced_when_the_log_list_expired(self):
        leaf = _leaf_with_embedded_scts([GOOGLE_1])
        self.assertIsNone(self.check(leaf, _logs(GOOGLE_1, expiration=NOW - timedelta(days=1))))
        self.assertIsNone(self.check(leaf, CTLogList()))

    def test_chain_of_one_certificate_is_not_compliant(self):
        leaf = _leaf_with_embedded_scts([GOOGLE_1, CLOUDFLARE])
        result = transparency.check_transparency(leaf, None, _logs(GOOGLE_1, CLOUDFLARE), now=NOW)
        self.assertFalse(result.compliant)


class TestDeliveredSCTs(unittest.TestCase):
    """SCTs sent in the TLS handshake or the stapled OCSP response."""

    def test_two_tls_scts_are_compliant(self):
        leaf = _leaf_builder(90).sign(CA_KEY, hashes.SHA256())
        scts = _sct_list([log.sct(0, _x509_entry(leaf)) for log in (GOOGLE_1, CLOUDFLARE)])
        result = transparency.check_transparency(leaf, CA, _logs(GOOGLE_1, CLOUDFLARE), tls_scts=scts, now=NOW)
        self.assertTrue(result.compliant, result.details())

    def test_tls_and_ocsp_scts_combine(self):
        leaf = _leaf_builder(400).sign(CA_KEY, hashes.SHA256())
        tls_scts = _sct_list([GOOGLE_1.sct(0, _x509_entry(leaf))])
        ocsp_scts = _sct_list([CLOUDFLARE.sct(0, _x509_entry(leaf))])
        result = transparency.check_transparency(leaf, CA, _logs(GOOGLE_1, CLOUDFLARE), tls_scts=tls_scts,
                                                 ocsp_scts=ocsp_scts, now=NOW)
        self.assertTrue(result.compliant)

    def test_sct_for_another_certificate(self):
        leaf = _leaf_builder(90).sign(CA_KEY, hashes.SHA256())
        other = _leaf_builder(30).sign(CA_KEY, hashes.SHA256())
        scts = _sct_list([log.sct(0, _x509_entry(other)) for log in (GOOGLE_1, CLOUDFLARE)])
        result = transparency.check_transparency(leaf, CA, _logs(GOOGLE_1, CLOUDFLARE), tls_scts=scts, now=NOW)
        self.assertFalse(result.compliant)
        self.assertEqual(result.invalid, 2)

    def test_malformed_lists(self):
        self.assertEqual(transparency.decode_sct_list(b"\x00\x05\x00"), ([], 1))
        self.assertEqual(transparency.decode_sct_list(None), ([], 0))


class TestChainLevel(unittest.TestCase):

    def validate(self, result):
        leaf = _leaf_builder(90).sign(CA_KEY, hashes.SHA256())
        chain = [{"id": LEAF, "origin": "Server", "cert": leaf},
                 {"id": ROOT, "origin": "Mozilla CA Bundle", "cert": CA}]
        with mock.patch.object(transparency, "check_transparency", return_value=result), \
                mock.patch("src.validation.certificate_validator._check_dnssec"), \
                mock.patch("src.validation.revocation.check_leaf_revocation", return_value=True), \
                mock.patch("src.validation.chain_validator._ip_address", return_value="192.0.2.1"):
            return ChainValidator.validate_chain("example.com", chain, [], True, False)

    def test_non_compliant_leaf_is_invalid(self):
        response = self.validate(transparency.CTResult(False, []))
        self.assertEqual(response["status"], "invalid")
        self.assertIn(transparency.CT_NOT_COMPLIANT, response["chain"][0]["issues"])

    def test_expired_log_list_is_reported(self):
        response = self.validate(None)
        self.assertIn(CT_NOT_CHECKED, response["analysis"])

    def test_bundled_log_list(self):
        logs = TrustStore.mozilla().ct_logs
        self.assertGreater(len(logs.logs), 10)
        self.assertGreater(len({log.operator_id for log in logs.logs.values()}), 2)


def _msg_output(messages):
    """openssl s_client -msg output for received handshake messages (label, type, body)."""
    lines = []
    for label, msg_type, body in messages:
        data = bytes([msg_type]) + len(body).to_bytes(3, "big") + body
        lines.append(f"<<< {label}, Handshake [length {len(data):04x}], X")
        for i in range(0, len(data), 16):
            lines.append("    " + " ".join(f"{b:02x}" for b in data[i:i + 16]))
    return "\n".join(lines) + "\n"


def _ext(ext_type, data):
    return ext_type.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data


class TestHandshakeParsing(unittest.TestCase):
    OCSP = b"\x30\x03\x0a\x01\x00"
    SCTS = b"\x00\x04\x00\x02\xab\xcd"

    def test_tls13_certificate_entry_extensions(self):
        status = b"\x01" + len(self.OCSP).to_bytes(3, "big") + self.OCSP
        extensions = _ext(5, status) + _ext(18, self.SCTS)
        entry = (3).to_bytes(3, "big") + b"abc" + len(extensions).to_bytes(2, "big") + extensions
        body = b"\x00" + len(entry).to_bytes(3, "big") + entry
        output = _msg_output([("TLS 1.3", 2, b"\x03\x03" + b"\x00" * 40), ("TLS 1.3", 11, body)])
        self.assertEqual(tls.parse_handshake(output), (self.OCSP, self.SCTS))

    def test_tls12_server_hello_and_certificate_status(self):
        extensions = _ext(18, self.SCTS)
        hello = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\xc0\x2f\x00" + len(extensions).to_bytes(2, "big") + extensions
        status = b"\x01" + len(self.OCSP).to_bytes(3, "big") + self.OCSP
        output = _msg_output([("TLS 1.2", 2, hello), ("TLS 1.2", 22, status)])
        self.assertEqual(tls.parse_handshake(output), (self.OCSP, self.SCTS))

    def test_nothing_sent(self):
        hello = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\xc0\x2f\x00"
        self.assertEqual(tls.parse_handshake(_msg_output([("TLS 1.2", 2, hello)])), (None, None))

    def test_only_the_chain_section_holds_the_certificates(self):
        """With -status, openssl first prints the OCSP responder's certificate."""
        pem = "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----"
        output = ("OCSP response:\n" + pem.format("RESPONDER") + "\n---\nCertificate chain\n 0 s:CN=leaf\n"
                  + pem.format("LEAF") + "\n 1 s:CN=CA\n" + pem.format("CA") + "\n---\nServer certificate\n")
        self.assertEqual(tls.chain_certificates(output), [pem.format("LEAF"), pem.format("CA")])

    def test_truncated_message_is_ignored(self):
        output = _msg_output([("TLS 1.3", 11, b"\x00\x00\x00\x09\x00")])
        self.assertEqual(tls.parse_handshake(output), (None, None))


class TestFirefoxClientHello(unittest.TestCase):
    """The ClientHello offers what Firefox offers, post-quantum group included when available."""

    def setUp(self):
        tls.supports_post_quantum.cache_clear()

    def tearDown(self):
        tls.supports_post_quantum.cache_clear()

    def groups(self, openssl_output, returncode=0):
        result = subprocess.CompletedProcess([], returncode, stdout=openssl_output, stderr="")
        with mock.patch("subprocess.run", return_value=result):
            args = tls.firefox_tls_args()
        return args[args.index("-groups") + 1]

    def test_post_quantum_group_and_key_shares(self):
        self.assertEqual(self.groups("secp256r1:x25519:MLKEM768:X25519MLKEM768:SecP256r1MLKEM768\n"),
                         "*X25519MLKEM768:*X25519:*P-256:P-384:P-521")

    def test_older_openssl_gets_classical_groups(self):
        self.assertEqual(self.groups("secp256r1:secp384r1:x25519\n"), "X25519:P-256:P-384:P-521")
        tls.supports_post_quantum.cache_clear()
        self.assertEqual(self.groups("", returncode=1), "X25519:P-256:P-384:P-521")

    def test_only_tls_1_2_and_1_3(self):
        with mock.patch.object(tls, "supports_post_quantum", return_value=False):
            args = tls.firefox_tls_args()
        self.assertTrue({"-no_ssl3", "-no_tls1", "-no_tls1_1"} <= set(args))

    def test_last_fallback_has_no_post_quantum_key_share(self):
        """For servers that break on the larger post-quantum ClientHello."""
        legacy = tls.OPENSSL_FALLBACK_ATTEMPTS[-1]
        groups = legacy[legacy.index("-groups") + 1]
        self.assertNotIn("MLKEM", groups.upper())
        self.assertNotIn("*", groups)

    def test_ecdsa_cbc_suites_are_not_offered(self):
        """Firefox disables ECDHE-ECDSA with AES-CBC."""
        self.assertNotIn("ECDHE-ECDSA-AES128-SHA:", tls.FIREFOX_CIPHERS + ":")
        self.assertNotIn("ECDHE-ECDSA-AES256-SHA:", tls.FIREFOX_CIPHERS + ":")


if __name__ == "__main__":
    unittest.main()
