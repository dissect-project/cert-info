"""
The CertificateValidator class is responsible for validating certificates in a chain.
"""

import re
import requests
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.ocsp import OCSPRequestBuilder, OCSPResponseStatus, OCSPCertStatus
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa, dsa
from cryptography.hazmat.primitives import hashes, serialization

from cert_info.NIST.parser import CSVParser

# Define certificate IDs
LEAF = "Leaf Certificate"
ROOT = "Root CA Certificate"


# Define constants for certificate validation issues
SIGNATURE_FAILED    = "Signature verification failed"
HOSTNAME_MISMATCH   = "Hostname mismatch"
EXPIRED             = "Certificate expired"
NOT_YET_VALID       = "Certificate not yet valid"
NOT_VALID_CA        = "Issuer is not a valid CA"
NO_CA_INFO          = "Certificate has no information about being a valid CA"
NIST_DISALLOWED     = "no longer allowed for applying cryptographic protection"
NIST_DEPRECATED     = "may be used, but user must accept security risks"
NIST_LEGACY         = "may be used only to process already protected information"
UNKNOWN_HASH        = "Could not determine signature hash algorithm."
UNKNOWN_SIGNATURE   = "Could not determine signature algorithm"
UNKNOWN_KEY         = "Could not determine public key algorithm"
CRL_REVOKED         = "Certificate is revoked (found in CRL)"
OCSP_REVOKED        = "Certificate is revoked (found in OCSP)"


# Define constants for certificate validation warnings
WILDCARD_USAGE        = "Certificate uses wildcard domain"
UPDATE_HASH_ALGORITHM = "Hash algorithm used in signature could be updated"

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
    
    def __is_secure_curve(self, curve) -> bool:
        """
        Checks if the given elliptic curve is considered secure.
        
        Args:
            curve ():

        Returns:
            bool: True if curve is secure, False otherwise
        """
        # List of secure curves 
        secure_curves = {
            ec.SECP256R1, ec.SECP384R1, ec.SECP521R1,  # NIST recommended curves
            ec.BrainpoolP256R1, ec.BrainpoolP384R1, ec.BrainpoolP512R1,  # Brainpool curves
            ec.SECP256K1  # Used in Bitcoin but not always recommended
        }
        # Check wether curve is parte of the secure list
        return isinstance(curve, tuple(secure_curves))

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
                issues.append(UNKNOWN_SIGNATURE)
            # Return True if no issues were found
            return len(issues) == 0
        except Exception:
            # Add issue to the list
            issues.append(SIGNATURE_FAILED)
            # Signature is invalid
            return False

    def __check_expiration(self, cert: x509.Certificate, issues: list) -> bool:
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

    def __check_revocation(self, cert: x509.Certificate, issuer_cert: x509.Certificate, issues: list, warnings: list) -> bool:
        """
        Check wether a certificate is revoked or nor.

        Args:
            cert (x509.Certificate): The certificate to check.
            issuer_cert (x509.Certificate): The certificate to of the issuer.
            issues (list): List to store issues found during validation.
            warnings (list): List to store warnings found during validation.

        Returns:
            bool: False if the validation fails, True otherwise.
        """
        # Extract CRL distribution points
        try:
            crl_distribution_points = cert.extensions.get_extension_for_class(
                x509.CRLDistributionPoints
            ).value if cert.extensions.get_extension_for_class(x509.CRLDistributionPoints) else None
        except x509.ExtensionNotFound:
            crl_distribution_points = []
        # Extract OCSP URL
        try:
            aia_extension = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            ).value
            # Get the OCSP server URLS
            ocsp_urls = [
                desc.access_location.value
                for desc in aia_extension
                if desc.access_method == AuthorityInformationAccessOID.OCSP
            ]
        except x509.ExtensionNotFound:
            ocsp_urls = []
        # Warn if both CRL and OCSP are missing
        if not crl_distribution_points and not ocsp_urls:
            issues.append("No CRL or OCSP information found in the certificate.")
        # Check revocation via CRL
        if crl_distribution_points:
            # Iterate the distribution points
            for crl_dp in crl_distribution_points:
                # Get the CRL URL
                crl_url = crl_dp.full_name[0].value  # Assuming first entry
                try:
                    # Make requests to the CRL server
                    response = requests.get(crl_url, timeout=5)
                    # Load the response
                    crl = x509.load_der_x509_crl(response.content)
                    # Check wether the certificate is present in the list
                    if any(rev_cert.serial_number == cert.serial_number for rev_cert in crl):
                        # Append issue
                        issues.append(CRL_REVOKED)
                        # Validation failed
                        return False
                except Exception as e:
                    warnings.append(f"Failed to check CRL at {crl_url}: {e}")
        # Check revocation via OCSP
        if ocsp_urls:
            # Initialize OCSP Request
            builder = OCSPRequestBuilder()
            # Add certificates to request
            builder = builder.add_certificate(cert, issuer_cert, hashes.SHA256())
            # Build request
            ocsp_request = builder.build()
            # Serialize request
            ocsp_request_data = ocsp_request.public_bytes(encoding=serialization.Encoding.DER)
            # Iterate OCSP URLs
            for ocsp_url in ocsp_urls:
                try:
                    # Send request to OCSP URL
                    response = requests.post(
                        ocsp_url,
                        data=ocsp_request_data,
                        headers={"Content-Type": "application/ocsp-request"},
                        timeout=5
                    )
                    # Get response
                    ocsp_response = x509.ocsp.load_der_ocsp_response(response.content)
                    # Check wether request was successfull
                    if ocsp_response.response_status == OCSPResponseStatus.SUCCESSFUL:
                        # Check wether certificate is revoked
                        if ocsp_response.certificate_status == OCSPCertStatus.REVOKED:
                            # Append the issue to the list
                            issues.append(OCSP_REVOKED)
                            # Verification failed
                            return False
                except Exception as e:
                    warnings.append(f"Failed to check OCSP at {ocsp_url}: {e}")
        # Return True if validation does not fail
        return len(issues) == 0

    def __check_signature_strength(self, cert: x509.Certificate, issues: list, warnings: list) -> bool:
        """
        Check wether the strength of the signature used in a certificate is
        adequate or not. 

        Args:
            cert (x509.Certificate): The certificate to check.
            issuer_cert (x509.Certificate): The certificate to of the issuer.
            issues (list): List to store issues found during validation.
            warnings (list): List to store warnings found during validation.

        Returns:
            bool: True if the signature strength is good, False otherwise.
        """
        # Check hash function
        try:
            # Get the signature algorithm
            sig_hash_algorithm = cert.signature_hash_algorithm
            # Get the hash function status
            status = CSVParser.get_hash_status(sig_hash_algorithm)
            # Check the hash function status
            if status == "Disallowed":
                # Add issue to the list
                issues.append("Hash " + NIST_DISALLOWED)
            elif status == "Deprecated":
                # Add issue to the list
                issues.append("Hash " + NIST_DEPRECATED)
            elif status == "Legacy":
                # Add issue to the list
                issues.append("Hash " + NIST_LEGACY)
        except Exception:
            issues.append(UNKNOWN_HASH)
        # Return True if no issues were found
        return len(issues) == 0
    
    def __check_key_strength(self, cert: x509.Certificate, issues: list, warnings: list) -> bool:
        """
        Check wether the strength of the key used in a certificate is
        adequate or not. First step consists in checking the 
        
        """
        # Check the digital signature algorithm
        try:
            # Get the public key
            public_key = cert.public_key()
            # Get the signature status
            status, i = CSVParser.get_key_status(public_key)
            # Check the hash function status
            if status == "Disallowed":
                # Add issue to the list
                issues.append("Key " + NIST_DISALLOWED)
            elif status == "Deprecated":
                # Add issue to the list
                issues.append("Key " + NIST_DEPRECATED)
            elif status == "Legacy":
                # Add issue to the list
                issues.append("Key " + NIST_LEGACY)
            # Check if issues were found
            if len(i) > 0:
                # Iterate through the issues
                for issue in i:
                    # Add issue to the list
                    issues.append(issue)
        except Exception:
            issues.append(UNKNOWN_KEY)
        # Return True if no issues were found
        return len(issues) == 0

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
        if cert_id != ROOT:
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
        status = self.__check_expiration(cert_obj, issues)
        ############## CA VALIDATION #####################
        # If the certificate is not a leaf certificate
        if cert_id != LEAF:
            # Check if the issuer is a valid CA
            status = self.__check_issuer_ca(issuer_cert_obj, issues)
        ############## COMMON NAME VALIDATION ############
        # If the certificate is a leaf certificate
        if cert_id == LEAF:
            expected_cn = domain
        else:
            # Get the issuer's Common Name (CN)
            expected_cn = cert_obj.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        # Check if expected name matches and is valid
        status = self.__check_common_name(cert_obj, expected_cn, issues, warnings)
        ############## REVOCATION VALIDATION #############
        # If the certificate is not a leaf certificate
        if cert_id != ROOT:
            # Check if the certificate is revoked
            status = self.__check_revocation(cert_obj, issuer_cert_obj, issues, warnings)
        ############## SIGNATURE VALIDATION ##############
        # Check if the signature strength is adequate
        status = self.__check_signature_strength(cert_obj, issues, warnings)
        ############## PUBLIC KEY VALIDATION #############
        # Check if the key strength is adequate
        status = self.__check_key_strength(cert_obj, issues, warnings)
        ##################################################
        # Return the status, issues, and warnings
        return status, issues, warnings
