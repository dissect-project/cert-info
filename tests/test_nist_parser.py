"""
Tests for the NIST classification of hashes, keys and curves
(src/validation/nist/parser.py) and how the validator reports it.
"""

import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from src.validation.certificate_validator import (
    NIST_DISALLOWED, ROOT, UNKNOWN_HASH, CertificateValidator,
    _report_hash_strength,
)
from src.trust.store import MOZILLA_ROOTS, load_pem_bundle
from src.validation.nist.parser import CSVParser


def _ec_key(curve):
    try:
        return ec.generate_private_key(curve).public_key()
    except UnsupportedAlgorithm:
        raise unittest.SkipTest(f"OpenSSL does not support {curve.name}")


class TestKeyStatus(unittest.TestCase):
    """CSVParser.get_key_status"""

    def assertKey(self, key, status, issues=()):
        self.assertEqual(CSVParser.get_key_status(key), (status, list(issues)))

    def test_rsa(self):
        self.assertKey(rsa.generate_private_key(65537, 2048).public_key(), "Acceptable")
        self.assertKey(rsa.generate_private_key(65537, 1024).public_key(), "Disallowed")

    def test_dsa_is_disallowed(self):
        """DSA used to fail on the empty key length and be reported as unknown."""
        self.assertKey(dsa.generate_private_key(2048).public_key(), "Disallowed")

    def test_eddsa(self):
        """EdDSA keys used to be reported as unknown."""
        self.assertKey(ed25519.Ed25519PrivateKey.generate().public_key(), "Acceptable")
        self.assertKey(ed448.Ed448PrivateKey.generate().public_key(), "Acceptable")

    def test_nist_prime_curves(self):
        for curve in (ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()):
            self.assertKey(_ec_key(curve), "Acceptable")

    def test_p192_is_disallowed(self):
        """P-192 used to be reported as unknown; it is legacy-use and too short to sign."""
        self.assertKey(_ec_key(ec.SECP192R1()), "Disallowed",
                       ["Usage of curve secp192r1 is Legacy"])

    def test_deprecated_binary_curve(self):
        """The curve status now also sets the key status."""
        self.assertKey(_ec_key(ec.SECT233K1()), "Deprecated",
                       ["Usage of curve sect233k1 is Deprecated"])

    def test_small_binary_curve(self):
        self.assertKey(_ec_key(ec.SECT163K1()), "Disallowed",
                       ["Usage of curve sect163k1 is Legacy"])

    def test_brainpool_is_allowed(self):
        self.assertKey(_ec_key(ec.BrainpoolP256R1()), "Acceptable")

    def test_secp256k1_is_disallowed(self):
        self.assertKey(_ec_key(ec.SECP256K1()), "Disallowed",
                       ["Usage of curve secp256k1 is Disallowed"])


class TestHashStatus(unittest.TestCase):
    """CSVParser.get_hash_status"""

    def test_hashes(self):
        expected = {
            hashes.MD5(): "Disallowed",
            hashes.SHA1(): "Disallowed",
            hashes.SHA224(): "Deprecated",
            hashes.SHA256(): "Acceptable",
            hashes.SHA512_224(): "Deprecated",
            hashes.SHA512_256(): "Acceptable",
            hashes.SHA3_256(): "Acceptable",
        }
        for hash_function, status in expected.items():
            self.assertEqual(CSVParser.get_hash_status(hash_function), status, hash_function.name)

    def test_missing_hash_is_unsupported(self):
        with self.assertRaises(ValueError):
            CSVParser.get_hash_status(None)


def _self_signed(key, algorithm):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root")])
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, algorithm)
    )


class TestSignatureHashReporting(unittest.TestCase):
    """Hash findings reported by the validator."""

    def test_eddsa_signature_has_no_hash_issue(self):
        """EdDSA signatures used to get 'Could not determine signature hash algorithm.'"""
        cert = _self_signed(ed25519.Ed25519PrivateKey.generate(), None)
        issues = []
        _report_hash_strength(cert, issues)
        self.assertNotIn(UNKNOWN_HASH, issues)
        self.assertEqual(issues, [])

    def test_root_self_signature_hash_is_not_checked(self):
        """A trusted root's SHA-1 self-signature is not relied upon."""
        root = _sha1_mozilla_root()
        _, issues, _ = CertificateValidator.validate("example.com", root, root, ROOT)
        self.assertNotIn("Hash " + NIST_DISALLOWED, issues)

    def test_sha1_signature_is_reported_on_other_certificates(self):
        issues = []
        _report_hash_strength(_sha1_mozilla_root(), issues)
        self.assertEqual(issues, ["Hash " + NIST_DISALLOWED])


def _sha1_mozilla_root():
    """A Mozilla root with a SHA-1 self-signature (cryptography cannot create one)."""
    for root in load_pem_bundle(MOZILLA_ROOTS):
        if isinstance(root.signature_hash_algorithm, hashes.SHA1):
            return root
    raise unittest.SkipTest("No SHA-1 root in the Mozilla bundle")

if __name__ == "__main__":
    unittest.main()
