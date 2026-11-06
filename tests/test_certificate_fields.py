"""
Tests for the validation level reported by src/validation/certificate_fields.py.
"""

import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from src.validation.certificate_fields import DV, EV, OV, CertificateFields

KEY = ec.generate_private_key(ec.SECP256R1())
NOW = datetime.now(timezone.utc)


def _cert(policy_oids=(), organization=None):
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]
    if organization:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    name = x509.Name(attributes)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(KEY.public_key())
        .serial_number(1)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
    )
    if policy_oids:
        builder = builder.add_extension(x509.CertificatePolicies([
            x509.PolicyInformation(x509.ObjectIdentifier(oid), None) for oid in policy_oids
        ]), critical=False)
    return builder.sign(KEY, hashes.SHA256())


class TestValidationLevel(unittest.TestCase):
    """CertificateFields.get_validation_level"""

    def test_ev_policy(self):
        """EV used to be reported as OV, because the O= rule overwrote the OID."""
        cert = _cert(["2.23.140.1.1"], organization="Example Inc")
        self.assertEqual(CertificateFields.get_validation_level(cert), EV)

    def test_ov_policy(self):
        cert = _cert(["2.23.140.1.2.2"], organization="Example Inc")
        self.assertEqual(CertificateFields.get_validation_level(cert), OV)

    def test_dv_policy_wins_over_organization(self):
        cert = _cert(["2.23.140.1.2.1"], organization="Example Inc")
        self.assertEqual(CertificateFields.get_validation_level(cert), DV)

    def test_highest_policy_wins(self):
        cert = _cert(["2.23.140.1.2.1", "2.23.140.1.1", "2.23.140.1.2.2"])
        self.assertEqual(CertificateFields.get_validation_level(cert), EV)

    def test_other_policies_are_ignored(self):
        cert = _cert(["1.3.6.1.4.1.44947.1.1.1"])
        self.assertEqual(CertificateFields.get_validation_level(cert), DV)

    def test_fallback_without_policy(self):
        self.assertEqual(CertificateFields.get_validation_level(_cert(organization="Example Inc")), OV)
        self.assertEqual(CertificateFields.get_validation_level(_cert()), DV)


# Self-signed certificate with a key on sect233k1 (a binary curve), made with
# openssl. cryptography can no longer load or generate such keys.
BINARY_CURVE_CERT = b"""-----BEGIN CERTIFICATE-----
MIIBcjCCAR+gAwIBAgIBATAKBggqhkjOPQQDAjAfMR0wGwYDVQQDDBRiaW5hcnkt
Y3VydmUuZXhhbXBsZTAeFw0yNjExMDYxNzQzMDFaFw0zNjExMDMxNzQzMDFaMB8x
HTAbBgNVBAMMFGJpbmFyeS1jdXJ2ZS5leGFtcGxlMFIwEAYHKoZIzj0CAQYFK4EE
ABoDPgAEACDfEuE0mu+oB4Em72zy+kzjUT6ZXi3G3bGVF9E1AGxJsXllCIWWMS5O
b+lmlns4IKHhYfq7pGS5icNwo1MwUTAdBgNVHQ4EFgQUl11vAWqVZ2HRkVs31mSs
C9TxBxEwHwYDVR0jBBgwFoAUl11vAWqVZ2HRkVs31mSsC9TxBxEwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNBADA+Ah0wm92AhFJ9sHnFsU5+GVk5+KL4zOMs
K1DXEYS4AgIdDYc4mKIWYfZRwBC3xWdVKKfWThIjyFJ4zmmB/c0=
-----END CERTIFICATE-----
"""


class TestDecode(unittest.TestCase):

    def test_fields(self):
        fields = CertificateFields.decode(_cert())
        self.assertEqual(fields["public_key_type"], type(KEY.public_key()).__name__)
        self.assertEqual(fields["public_key_size"], 256)

    def test_unsupported_key_does_not_fail(self):
        """A key cryptography cannot load is reported instead of raising."""
        cert = x509.load_pem_x509_certificate(BINARY_CURVE_CERT)
        try:
            cert.public_key()
        except UnsupportedAlgorithm:
            pass
        else:
            self.skipTest("this cryptography release can still load binary curve keys")
        fields = CertificateFields.decode(cert)
        self.assertEqual(fields["public_key_type"], "Unsupported")
        self.assertEqual(fields["public_key_size"], "N/A")
        self.assertEqual(fields["subject"], "CN=binary-curve.example")


if __name__ == "__main__":
    unittest.main()
