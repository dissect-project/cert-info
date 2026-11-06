"""
Decodes a certificate into the fields reported in chain[].certificate.
"""

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from src.chain.certificate_rules import extension

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

EV = "Extended Validation (EV)"
OV = "Organization Validation (OV)"
DV = "Domain Validation (DV)"
# CA/Browser Forum policy OIDs, highest level first
VALIDATION_LEVEL_OIDS = (
    ("2.23.140.1.1", EV),
    ("2.23.140.1.2.2", OV),
    ("2.23.140.1.2.1", DV),
)


class CertificateFields:
    """Decode an X.509 certificate into a JSON-serialisable dict."""

    @staticmethod
    def decode(cert: x509.Certificate) -> dict:
        """
        Extract the reported fields from a certificate.

        Args:
            cert (x509.Certificate): The certificate.

        Returns:
            dict: The certificate fields.
        """
        try:
            public_key = cert.public_key()
            key_type, key_size = type(public_key).__name__, getattr(public_key, "key_size", "N/A")
        except (ValueError, UnsupportedAlgorithm):
            # A key cryptography cannot load, e.g. on a binary curve (sect*),
            # which cryptography no longer supports (nor does Firefox)
            key_type, key_size = "Unsupported", "N/A"
        cert_data = {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": format(cert.serial_number, "x"),  # hex string, avoids float precision loss
            "valid_from": cert.not_valid_before_utc.strftime(DATE_FORMAT),
            "valid_until": cert.not_valid_after_utc.strftime(DATE_FORMAT),
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "public_key_type": key_type,
            "public_key_size": key_size,
            "type": CertificateFields.get_certificate_type(cert),
        }

        san = extension(cert, x509.SubjectAlternativeName)
        if san:
            cert_data["SAN"] = [str(name.value) for name in san]

        key_usage = extension(cert, x509.KeyUsage)
        if key_usage:
            cert_data["key_usage"] = {
                "digital_signature": key_usage.digital_signature,
                "key_encipherment": key_usage.key_encipherment,
                "data_encipherment": key_usage.data_encipherment,
                "key_cert_sign": key_usage.key_cert_sign,
                "crl_sign": key_usage.crl_sign,
            }
        extended_key_usage = extension(cert, x509.ExtendedKeyUsage)
        if extended_key_usage:
            cert_data["extended_key_usage"] = [str(eku._name) for eku in extended_key_usage]

        crl_points = extension(cert, x509.CRLDistributionPoints)
        if crl_points:
            cert_data["crl_distribution_points"] = [
                point.full_name[0].value for point in crl_points if point.full_name
            ]
        aia = extension(cert, x509.AuthorityInformationAccess)
        if aia:
            ocsp_urls = [desc.access_location.value for desc in aia
                         if desc.access_method == AuthorityInformationAccessOID.OCSP]
            ca_issuers_urls = [desc.access_location.value for desc in aia
                               if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS]
            if ocsp_urls:
                cert_data["ocsp_urls"] = ocsp_urls
            if ca_issuers_urls:
                cert_data["ca_issuers_urls"] = ca_issuers_urls

        cert_data["validation_level"] = CertificateFields.get_validation_level(cert)
        cert_data["fingerprint_SHA256"] = cert.fingerprint(hashes.SHA256()).hex()
        cert_data["signature"] = cert.signature.hex()
        return cert_data

    @staticmethod
    def get_certificate_type(cert: x509.Certificate) -> str:
        """
        "Root CA" if subject equals issuer, "Intermediate Certificate" if Basic
        Constraints has cA set, "Leaf Certificate" otherwise.
        """
        if cert.issuer == cert.subject:
            return "Root CA"
        constraints = extension(cert, x509.BasicConstraints)
        if constraints and constraints.ca:
            return "Intermediate Certificate"
        return "Leaf Certificate"

    @staticmethod
    def get_validation_level(cert: x509.Certificate) -> str:
        """
        Validation level from the CA/Browser Forum policy OIDs in Certificate
        Policies. If several are present (common in CA certificates), the
        highest level wins. Without any of them, the level is inferred from
        the subject: OV if it has an Organization attribute, DV otherwise.
        """
        policies = extension(cert, x509.CertificatePolicies) or []
        oids = {policy.policy_identifier.dotted_string for policy in policies}
        for oid, level in VALIDATION_LEVEL_OIDS:
            if oid in oids:
                return level
        if cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME):
            return OV
        return DV
