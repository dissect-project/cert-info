"""
The CertificateValidator class is responsible for validating certificates in a chain.
"""

import re
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.hazmat.primitives import hashes

# Define constants for certificate validation issues
SIGNATURE_FAILED  = "Signature verification failed"
HOSTNAME_MISMATCH = "Hostname mismatch"
EXPIRED           = "Certificate expired"
NOT_YET_VALID     = "Certificate not yet valid"
NOT_VALID_CA      = "Issuer is not a valid CA"
NO_CA_INFO        = "Certificate has no information about being a valid CA"

# Define constants for certificate validation warnings
WILDCARD_USAGE    = "Certificate uses wildcard domain"

class CertificateValidator:
    """
    CertificateValidator class to validate certificates in a chain. This class provides 
    methods to validate various aspects of a certificate in its respective chain.
    """
    def __init__(self, chain: list):
        # Inititalize the certificate chain
        self.chain = chain

    def __is_wildcard(self, wildcard: str, hostname: str) -> bool:
        """
        Check if a wildcard domain (e.g., *.example.com) matches a given 
        hostname (e.g., sub.example.com).

        Args:
            wildcard (str): The wildcard domain to check
            hostname (str): The hostname to check against the wildcard

        Returns:
            bool: True if the hostname matches the wildcard domain, False otherwise
        """
        # Check if the wildcard starts with "*."
        if not wildcard.startswith("*."):
            return False  # Not a wildcard, should match exactly
        # Remove the "*." from the wildcard domain
        domain = wildcard[2:]
        # Convert wildcard domain to regex (e.g., "*.example.com" → "^.*\.example\.com$")
        wildcard_regex = r"^.*\." + re.escape(domain) + r"$"  # Use raw string here
        # Check if the hostname matches the regex (subdomains allowed)
        return re.match(wildcard_regex, hostname) is not None

    def __verify_certificate_signature(self, cert: x509.Certificate, issuer_cert: x509.Certificate, issues: list) -> bool:
        """
        Verify if the given certificate was signed by the issuer certificate.
        
        Args:
            cert (x509.Certificate): The certificate to verify
            issuer_cert (x509.Certificate): The issuer certificate
        
        Returns:
            bool: True if the signature is valid, False otherwise
        """
        # Get the public key of the issuer certificate
        issuer_public_key = issuer_cert.public_key()
        # Perform the signature verification
        try:
            # Check if the issuer's public key is of type ECDSA
            if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):  # ECDSA
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm)
                )
            # Check if the issuer's public key is of type RSA
            elif isinstance(issuer_public_key, rsa.RSAPublicKey):  # RSA
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm
                )
            else:
                # Add issue to the list
                issues.append(SIGNATURE_FAILED)
                # Unsupported public key type
                return False
            # Signature is valid
            return True
        except Exception:
            # Add issue to the list
            issues.append(SIGNATURE_FAILED)
            # Signature is invalid
            return False

    def __certificate_expiration(self, cert: x509.Certificate, issues: list) -> bool:
        """
        Check if the certificate is expired.

        Args:
            cert (x509.Certificate): The certificate to check
            issues (list): List to store issues found during validation

        Returns:
            bool: True if the certificate is expired, False otherwise
        """
        # Verify certificate expiration
        if cert.not_valid_after_utc < datetime.now(timezone.utc):
            # Add issue to the list
            issues.append(EXPIRED)
            # Update the status
            return False
        # Verify certificate not yet valid
        if cert.not_valid_before_utc > datetime.now(timezone.utc):
            # Add issue to the list
            issues.append(NOT_YET_VALID)
            # Update the status
            return False
        # Certificate is valid
        return True

    def __check_issuer_ca(self, cert: x509.Certificate, issues: list) -> bool:
        """
        Check if the issuer is a valid CA.

        Args:
            cert (x509.Certificate): The certificate to check
            issues (list): List to store issues found during validation

        Returns:
            bool: True if the issuer is a valid CA, False otherwise
        """
        # Check if the certificate has the CA basic constraint
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.BASIC_CONSTRAINTS
            ).value
            # Check if the issuer is a CA
            if not basic_constraints.ca:
                # Add issue to the list
                issues.append(NOT_VALID_CA)
            # Return the status
            return basic_constraints.ca
        except x509.ExtensionNotFound:
            # If the extension is missing, it's likely a leaf certificate.
            issues.append(NO_CA_INFO)
            # Return False
            return False

    def __check_common_name(self, cert: x509.Certificate, expected: str, issues: list, warnings: list) -> bool:
        """
        Check if the certificate's Common Name (CN) or Subject Alternative Name (SAN) matches the expected value.

        Args:
            cert (x509.Certificate): The certificate to check.
            expected (str): The expected hostname/domain.
            issues (list): List to store issues found during validation.
            warnings (list): List to store warnings found during validation.

        Returns:
            bool: True if the hostname matches, False otherwise.
        """
        # Try to get Subject Alternative Name (SAN)
        try:
            # Get the SAN extension
            san_extension = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
            san_dns_names = san_extension.value.get_values_for_type(x509.DNSName)
            # Iterate through the SAN DNS names
            for san in san_dns_names:
                # Check if SAN is wildcard
                wildcard = self.__is_wildcard(san, expected)
                # Check if the expected hostname matches the SAN (exact or wildcard match)
                if san == expected or wildcard:
                    # Check if wildcard is used
                    if wildcard:
                        # Add warning to list
                        warnings.append(WILDCARD_USAGE)
                    # Return True if it matches
                    return True
        except x509.ExtensionNotFound:
            pass  # SAN not found, fallback to CN
        # Check the Common Name (CN) only if SAN is missing
        cn_attributes = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        # Check if CN is present
        if cn_attributes:
            # Get the CN value
            subject_cn = cn_attributes[0].value
            # Cheeck if the CN is wildcard
            wildcard = self.__is_wildcard(subject_cn, expected)
            # Check if the expected hostname matches the CN (exact or wildcard match)
            if subject_cn == expected or wildcard:
                # Check if wildcard is used
                if wildcard:
                    # Add warning to list
                    warnings.append(WILDCARD_USAGE)
                # Return True if it matches
                return True
        # If no match was found, add issue and return False
        issues.append(HOSTNAME_MISMATCH)
        return False

    def validate(self, domain: str, pos: int, cert_id: str) -> tuple:
        """
        Validate the certificate in the respective chain.

        Args:
            domain (str): The domain to be validated
            pos (int): Position of the certificate in the chain
            cert_id (str): The ID of the certificate

        Returns:
            tuple: The certificate information, issuesm and warnings found during validation
        """
        # Initialize the certificate issues list
        issues = []
        # Initialize the certificate warnings list
        warnings = []
        # Initialize the certificate validation status
        status = True
        # Load the certificate
        cert_obj = x509.load_pem_x509_certificate(self.chain[pos]['pem'].encode())
        # Check wether the certificate is from a root CA
        if cert_id != "Root CA Certificate":
            # Load the issuer certificate
            issuer_cert_obj = x509.load_pem_x509_certificate(self.chain[pos+1]['pem'].encode())
        else:
            # The issuer is the root CA itself
            issuer_cert_obj = cert_obj
        ############## SIGNATURE VALIDATION ##############
        # Verify if certificate was signed by the issuer
        status = self.__verify_certificate_signature(cert_obj, issuer_cert_obj, issues)
        ############## EXPIRATION VALIDATION #############
        # Check if the certificate is expired
        status = self.__certificate_expiration(cert_obj, issues)
        ############## CA VALIDATION #####################
        # If the certificate is not a leaf certificate
        if cert_id != "Leaf Certificate":
            # Check if the issuer is a valid CA
            status = self.__check_issuer_ca(issuer_cert_obj, issues)
        ############## COMMON NAME VALIDATION ############
        # If the certificate is a leaf certificate
        if cert_id == "Leaf Certificate":
            expected_cn = domain
        else:
            # Get the issuer's Common Name (CN)
            expected_cn = cert_obj.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        # Check if expected name matches and is valid
        status = self.__check_common_name(cert_obj, expected_cn, issues, warnings)
        ##################################################
        # Return the status, issues, and warnings
        return status, issues, warnings
