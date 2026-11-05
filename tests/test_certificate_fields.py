"""
Tests for the validation level reported by src/validation/certificate_fields.py.
"""

import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
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


if __name__ == "__main__":
    unittest.main()
