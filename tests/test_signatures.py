"""
Tests for signature verification (src/chain/signatures.py) as used by the
validator. It must accept every signature scheme used by real CAs, not only
RSA PKCS#1 v1.5 and ECDSA.
"""

import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID

from src.validation.certificate_validator import (
    ROOT, SIGNATURE_FAILED, UNKNOWN_SIGNATURE, CertificateValidator, _check_signature,
)
from src.chain.certificate_rules import SHA1_SIGNATURE, signature_problems
from src.chain.signatures import is_self_signed
from src.trust.store import MOZILLA_ROOTS, load_pem_bundle

NOW = datetime.now(timezone.utc)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, subject_key, issuer, issuer_key, **sign_kwargs):
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
    )
    return builder.sign(issuer_key, **sign_kwargs)


class TestSignatureCheck(unittest.TestCase):
    """_check_signature on different signature schemes."""

    @classmethod
    def setUpClass(cls):
        cls.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.ec_key = ec.generate_private_key(ec.SECP256R1())
        cls.ed_key = ed25519.Ed25519PrivateKey.generate()
        cls.leaf_key = ec.generate_private_key(ec.SECP256R1())

    def check(self, child, issuer):
        issues = []
        return _check_signature(child, issuer, issues), issues

    def test_rsa_pkcs1v15(self):
        ca = _cert("CA", self.rsa_key, "CA", self.rsa_key, algorithm=hashes.SHA256())
        leaf = _cert("leaf", self.leaf_key, "CA", self.rsa_key, algorithm=hashes.SHA256())
        self.assertEqual(self.check(leaf, ca), (True, []))

    def test_rsa_pss(self):
        """RSA-PSS used to be reported as a failed signature."""
        pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
        ca = _cert("CA", self.rsa_key, "CA", self.rsa_key, algorithm=hashes.SHA256(),
                   rsa_padding=pss)
        leaf = _cert("leaf", self.leaf_key, "CA", self.rsa_key, algorithm=hashes.SHA256(),
                     rsa_padding=pss)
        self.assertEqual(self.check(leaf, ca), (True, []))

    def test_ecdsa(self):
        ca = _cert("CA", self.ec_key, "CA", self.ec_key, algorithm=hashes.SHA384())
        leaf = _cert("leaf", self.leaf_key, "CA", self.ec_key, algorithm=hashes.SHA384())
        self.assertEqual(self.check(leaf, ca), (True, []))

    def test_ed25519(self):
        """Ed25519 used to be reported as an unknown signature algorithm."""
        ca = _cert("CA", self.ed_key, "CA", self.ed_key, algorithm=None)
        leaf = _cert("leaf", self.leaf_key, "CA", self.ed_key, algorithm=None)
        self.assertEqual(self.check(leaf, ca), (True, []))

    def test_self_signed_root(self):
        root = _cert("Root", self.ec_key, "Root", self.ec_key, algorithm=hashes.SHA256())
        self.assertEqual(self.check(root, root), (True, []))

    def test_wrong_key(self):
        """Same issuer name, different key: the signature does not verify."""
        ca = _cert("CA", self.ec_key, "CA", self.ec_key, algorithm=hashes.SHA256())
        other_key = ec.generate_private_key(ec.SECP256R1())
        leaf = _cert("leaf", self.leaf_key, "CA", other_key, algorithm=hashes.SHA256())
        self.assertEqual(self.check(leaf, ca), (False, [SIGNATURE_FAILED]))

    def test_wrong_issuer_name(self):
        ca = _cert("Other CA", self.ec_key, "Other CA", self.ec_key, algorithm=hashes.SHA256())
        leaf = _cert("leaf", self.leaf_key, "CA", self.ec_key, algorithm=hashes.SHA256())
        self.assertEqual(self.check(leaf, ca), (False, [SIGNATURE_FAILED]))

    def test_mismatched_key_type(self):
        """An issuer whose key type cannot have produced the signature."""
        ca = _cert("CA", self.ec_key, "CA", self.ec_key, algorithm=hashes.SHA256())
        leaf = _cert("leaf", self.leaf_key, "CA", self.rsa_key, algorithm=hashes.SHA256())
        valid, issues = self.check(leaf, ca)
        self.assertFalse(valid)
        self.assertIn(issues, ([SIGNATURE_FAILED], [UNKNOWN_SIGNATURE]))


class TestSha1Roots(unittest.TestCase):
    """
    18 Mozilla roots sign themselves with SHA-1 (e.g. DigiCert Global Root CA).
    Certificate.verify_directly_issued_by refuses SHA-1, which made these
    roots invalid ("Could not determine signature algorithm").
    """

    @classmethod
    def setUpClass(cls):
        roots = load_pem_bundle(MOZILLA_ROOTS)
        cls.sha1_roots = [r for r in roots if isinstance(r.signature_hash_algorithm, hashes.SHA1)]
        if not cls.sha1_roots:
            raise unittest.SkipTest("No SHA-1 root in the Mozilla bundle")

    def test_sha1_roots_are_self_signed(self):
        for root in self.sha1_roots:
            self.assertTrue(is_self_signed(root), root.subject.rfc4514_string())
            self.assertEqual(signature_problems(root), [SHA1_SIGNATURE])

    def test_sha1_root_is_valid(self):
        root = self.sha1_roots[0]
        valid, issues, _ = CertificateValidator.validate("example.com", root, root, ROOT)
        self.assertTrue(valid, issues)
        self.assertNotIn(UNKNOWN_SIGNATURE, issues)
        self.assertNotIn(SIGNATURE_FAILED, issues)


if __name__ == "__main__":
    unittest.main()
