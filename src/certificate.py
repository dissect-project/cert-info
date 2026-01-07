"""
This module provides a Certificate class that can be used to decode a
PEM-encoded certificate and extract all available fields.
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes

class Certificate:
    """
    Certificate class that provides methods to decode a PEM-encoded
    certificate and extract all available fields.
    """

    @staticmethod
    def get_issuer(raw_cert: str) -> str:
        """
        Extract the issuer from a certificate.

        Args:
            raw_cert (str): The raw certificate data.

        Returns:
            str: The issuer name.
        """
        # Initialize issuer
        issuer = ""
        # Load the certificate
        cert = x509.load_pem_x509_certificate(raw_cert.encode())
        # Iterate over the subject fields to find the Common Name (CN)
        for attribute in cert.issuer:
            # Check if the attribute is the Common Name
            if attribute.oid == x509.NameOID.COMMON_NAME:
                # Return the issuer name
                issuer = attribute.value
            elif attribute.oid == x509.NameOID.ORGANIZATIONAL_UNIT_NAME:
                # Return organizational unit name
                issuer = attribute.value
        # Return the issuer name
        return issuer
    
    @staticmethod
    def get_subject(raw_cert: str) -> str:
        """
        Extract the subject from a certificate.

        Args:
            raw_cert (str): The raw certificate data.

        Returns:
            str: The issuer name.
        """
        # Initialize issuer
        issuer = ""
        # Load the certificate
        cert = x509.load_pem_x509_certificate(raw_cert.encode())
        # Iterate over the subject fields to find the Common Name (CN)
        for attribute in cert.subject:
            # Check if the attribute is the Common Name
            if attribute.oid == x509.NameOID.COMMON_NAME:
                # Return the issuer name
                issuer = attribute.value
            elif attribute.oid == x509.NameOID.ORGANIZATIONAL_UNIT_NAME:
                # Return organizational unit name
                issuer = attribute.value
        # Return the issuer name
        return issuer

    @staticmethod
    def get_certificate_type(cert: x509.Certificate) -> str:
        """
        Determine whether a certificate is a leaf, intermediate, or root.

        Args:
            cert (x509.Certificate): The certificate object.

        Returns:
            str: The certificate type.
        """
        # Check if self-signed (Root CA)
        if cert.issuer == cert.subject:
            return "Root CA"
        try:
            # Check if the certificate has the CA basic constraint
            basic_constraints = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.BASIC_CONSTRAINTS
            ).value

            if basic_constraints.ca:
                return "Intermediate Certificate"
            else:
                return "Leaf Certificate"
        except x509.ExtensionNotFound:
            # If the extension is missing, it's likely a leaf certificate.
            return "Leaf Certificate"

    @staticmethod
    def get_basic_info(cert: x509.Certificate) -> dict:
        """
        Get the basic information from the certificate.

        Args:
            oid (x509.ExtensionOID): The OID of the extension.
            cert (x509.Certificate): The certificate object.

        Returns:
            dict: The certificate information.
        """
        # Format dates
        valid_from = cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S")
        valid_until = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S")
        # Public Key Information
        public_key = cert.public_key()
        key_type = type(public_key).__name__
        key_size = getattr(public_key, "key_size", "N/A")  # RSA & EC have key_size attribute
        # Basic Certificate Information
        cert_data = {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": cert.serial_number,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "public_key_type": key_type,
            "public_key_size": key_size,
        }
        # Return the certificate information
        return cert_data

    @staticmethod
    def get_extension(oid: x509.ExtensionOID, cert) -> str:
        """
        Helper function to get an extension safely.

        Args:
            oid (x509.ExtensionOID): The OID of the extension.
        
        Returns:
            str: The value of the extension.
        """
        try:
            # Get the extension for the specified OID
            return cert.extensions.get_extension_for_oid(oid).value
        except x509.ExtensionNotFound:
            # Return None if the extension is not found
            return None

    @staticmethod
    def get_key_usage(cert: x509.Certificate, cert_data: dict) -> None:
        """
        Get the key usage information from the certificate.

        Args:
            cert (x509.Certificate): The certificate information object.
            cert_object (dict): The certificate object to be updated.
        
        Returns:
            None
        """
        # Key Usage
        key_usage = Certificate.get_extension(x509.ExtensionOID.KEY_USAGE, cert)
        if key_usage:
            cert_data["key_usage"] = {
                "digital_signature": key_usage.digital_signature,
                "key_encipherment": key_usage.key_encipherment,
                "data_encipherment": key_usage.data_encipherment,
                "key_cert_sign": key_usage.key_cert_sign,
                "crl_sign": key_usage.crl_sign,
            }
        # Extended Key Usage
        extended_key_usage = Certificate.get_extension(x509.ExtensionOID.EXTENDED_KEY_USAGE, cert)
        if extended_key_usage:
            cert_data["extended_key_usage"] = [str(eku._name) for eku in extended_key_usage]

    @staticmethod
    def get_crl_and_aia_info(cert: x509.Certificate, cert_data: dict) -> None:
        """
        Get the CRL Distribution Points and Authority Information Access
        information from the certificate.

        Args:
            cert (x509.Certificate): The certificate object.
            cert_data (dict): The certificate information object.
        
        Returns:
            None
        """
        # CRL Distribution Points
        crl_distribution_points = Certificate.get_extension(
            x509.ExtensionOID.CRL_DISTRIBUTION_POINTS, cert)
        if crl_distribution_points:
            cert_data["crl_distribution_points"] = [
                dp.full_name[0].value for dp in crl_distribution_points if dp.full_name
            ]
        # Authority Information Access (OCSP and CA Issuers)
        aia = Certificate.get_extension(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS, cert)
        if aia:
            ocsp_urls = [desc.access_location.value for desc in aia\
                         if desc.access_method == x509.OID_OCSP]
            ca_issuers_urls = [desc.access_location.value for desc in aia\
                               if desc.access_method == x509.OID_CA_ISSUERS]
            if ocsp_urls:
                cert_data["ocsp_urls"] = ocsp_urls
            if ca_issuers_urls:
                cert_data["ca_issuers_urls"] = ca_issuers_urls

    @staticmethod
    def get_validation_level(cert: x509.Certificate, cert_data: dict) -> None:
        """
        Identify if a certificate is DV, OV, or EV based on OID.

        Args:
            cert (x509.Certificate): The certificate object.
            cert_data (dict): The certificate information object.

        Returns:
            None
        """
        # Initialize the validation level
        validation_level = "Unknown"
        try:
            # Retrieve the certificate policies extension
            policies = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.CERTIFICATE_POLICIES).value
            # Iterate policies to find the validation level
            for policy in policies:
                # Get the OID of the policy
                oid = policy.policy_identifier.dotted_string
                # Check if the OID corresponds to a validation level
                if oid == "2.23.140.1.1":
                    validation_level = "Extended Validation (EV)"
                elif oid == "2.23.140.1.2.2":
                    validation_level = "Organization Validation (OV)"
                elif oid == "2.23.140.1.2.1":
                    validation_level = "Domain Validation (DV)"
        except x509.ExtensionNotFound:
            pass

        # If no OID is found but subjet contains 'O' field, assume OV, otherwise DV.
        subject = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        validation_level =  "Organization Validation (OV)" if subject else "Domain Validation (DV)"
        # Add the validation level to the certificate data
        cert_data["validation_level"] = validation_level


    @staticmethod
    def decode(cert_pem: str) -> dict:
        """
        Decode a PEM-encoded certificate and extract all available fields.

        Args:
            cert_pem (str): The PEM-encoded certificate.

        Returns:
            dict: The extracted certificate information.
        """
        # Load the certificate
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        # Get the basic certificate information
        cert_data = Certificate.get_basic_info(cert)
        # Get the certificate type
        cert_data["type"] = Certificate.get_certificate_type(cert)
        # Subject Alternative Names (SAN)
        san_ext = Certificate.get_extension(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME, cert)
        if san_ext:
            cert_data["SAN"] = [name.value for name in san_ext]
        # Key Usage
        Certificate.get_key_usage(cert, cert_data)
        # Basic Constraints
        basic_constraints = Certificate.get_extension(x509.ExtensionOID.BASIC_CONSTRAINTS, cert)
        if basic_constraints:
            cert_data["is_ca"] = basic_constraints.ca
            cert_data["path_length"] = basic_constraints.path_length
        # Get CRL and AIA information
        Certificate.get_crl_and_aia_info(cert, cert_data)
        # Get the validation level
        Certificate.get_validation_level(cert, cert_data)
        # Get the certificate fingerprint
        cert_data["fingerprint_SHA256"] = cert.fingerprint(hashes.SHA256()).hex()
        # Add signature to certificate info (in hexadecimal format)
        cert_data["signature"] = cert.signature.hex()
        # Return the certificate information
        return cert_data
