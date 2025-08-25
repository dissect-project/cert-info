"""
This module contains all the code required to validate the certificate chain
of a given domain.
"""

import re
import socket
import json
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
import certifi
import requests

from cert_info.root_ca import RootCA
from cert_info.certificate import Certificate
from cert_info.certificate_validation import CertificateValidator

# Initialize certifi
ca_bundle_path = certifi.where()

class ChainValidator:
    """
    ChainValidator class that provides methods to validate the certificate
    chain of a given domain.
    """

    @staticmethod
    def extract_cert_by_subject(cert_data: str, subject: str) -> str:
        """
        Extracts a certificate from a string based on the Common Name (CN).

        Args:
            cert_data (str): The string containing multiple PEM certificates.
            subject (str): The subject to search for in the certificates.

        Returns:
            str: The PEM certificate that matches the subject, or None if not found.
        """
        # Find all PEM certificates in the string
        pem_certs = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            cert_data,
            re.DOTALL
        )
        # Iterate through the found PEM certificates
        for pem in pem_certs:
            # Load the certificate
            cert = x509.load_pem_x509_certificate(pem.encode())
            # Convert the full subject to a string for easy comparison
            full_subject = cert.subject.rfc4514_string()  # e.g., "CN=..., O=..., C=..."
            # Check if the CN matches the provided common name
            if full_subject == subject:
                return pem  # Return PEM of matching cert
        return None  # No match found

    @staticmethod
    def load_mozilla_ca_certs() -> list:
        """
        Load Mozilla CA certificates from the certifi package.

        Returns:
            list: A list of loaded CA certificates.
        """
        with open(certifi.where(), "rb") as f:
            pem_data = f.read()

        certs = []
        for cert in pem_data.split(b"-----END CERTIFICATE-----"):
            if cert.strip():
                cert += b"-----END CERTIFICATE-----\n"
                try:
                    cert_obj = x509.load_pem_x509_certificate(cert)
                    certs.append(cert_obj)
                except Exception as e:
                    print(f"Failed to parse cert: {e}")
        return certs

    @staticmethod
    def fetch_issuer_certificate(cert: str) -> tuple[x509.Certificate, bool]:
        """
        Fetch the issuer certificate using AIA information.

        Args:
            cert (str): The certificate to fetch the issuer for.

        Returns:
            str: The PEM formatted issuer certificate if found, None otherwise.
            bool: True if the issuer is a trusted CA, False otherwise.
        """
        # Load the certificate
        cert = x509.load_pem_x509_certificate(cert.encode())
        # Check if CN has content
        if len(cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)) > 0:
            # Extract the issuer name
            issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            subject = cert.issuer.rfc4514_string()
        else:
            issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
            subject = cert.issuer.rfc4514_string()
        #Check if certificate is in local trust store
        local = RootCA.get_certificate(issuer)
        # Check if the issuer is a root CA
        if local is not None:
            # Fetch the matching certificate from the local trust store
            local = ChainValidator.extract_cert_by_subject(local, subject)
            # If it is in trust store, return the certificate
            return x509.load_pem_x509_certificate(local.encode('utf-8')), True
        else:
            # Extract the AIA extension
            aia = Certificate.get_extension(
                x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS, cert
            )
            # Check if AIA is present
            if aia:
                ca_issuers_urls = [desc.access_location.value for desc in aia\
                                if desc.access_method == x509.OID_CA_ISSUERS]
                if len(ca_issuers_urls) > 0:
                    # Fetch the first CA issuer URL
                    ca_issuer_url = ca_issuers_urls[0]
                    try:
                        # Retrieve the issuer certificate from the URL
                        response = requests.get(ca_issuer_url, verify=ca_bundle_path, timeout=30)
                        if response.status_code == 200:
                            try:
                                # Try PEM
                                fetched = x509.load_pem_x509_certificate(response.content)
                            except ValueError:
                                pass

                            try:
                                # Try DER
                                fetched = x509.load_der_x509_certificate(response.content)
                            except ValueError:
                                pass

                            try:
                                # Try both PEM and DER encoded PKCS#7
                                if b'-----BEGIN PKCS7' in response.content:
                                    fetched = pkcs7.load_pem_pkcs7_certificates(response.content)
                                else:
                                    fetched = pkcs7.load_der_pkcs7_certificates(response.content)
                                # Check if fetched is a list
                                if isinstance(fetched, list):
                                    fetched = fetched[0]
                            except ValueError:
                                pass
                            # Return the fetched certificate
                            return fetched, False
                        else:
                            print(f"Failed to fetch issuer certificate: {response.status_code}")
                            return None, False
                    except requests.RequestException as e:
                        print(f"Error fetching issuer certificate: {e}")
                        return None, False
                else:
                    return None, False
            else:
                print("No AIA extension found in the certificate.")
                return None, False

    @staticmethod
    def is_signed_by(cert: str, issuer: str) -> bool:
        """
        Checks if a certificate is signed by a given issuer.

        Args:
            cert (str): The certificate to be checked
            issuer (str): The issuer to be checked against

        Returns:
            bool: True if the certificate is signed by the issuer, False otherwise
        """
        # Load the certificates
        cert_obj = x509.load_pem_x509_certificate(cert.encode())
        issuer_obj = x509.load_pem_x509_certificate(issuer.encode())
        # Get the public key of the issuer certificate
        issuer_public_key = issuer_obj.public_key()
        # Perform the signature verification
        try:
            # Check if the issuer's public key is of type ECDSA
            if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):  # ECDSA
                issuer_public_key.verify(
                    cert_obj.signature,
                    cert_obj.tbs_certificate_bytes,
                    ec.ECDSA(cert_obj.signature_hash_algorithm)
                )
            # Check if the issuer's public key is of type RSA
            elif isinstance(issuer_public_key, rsa.RSAPublicKey):  # RSA
                issuer_public_key.verify(
                    cert_obj.signature,
                    cert_obj.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert_obj.signature_hash_algorithm
                )
            else:
                return False
            # If no exception is raised, the certificate is signed by the issuer
            return True
        except Exception as e:
            return False

    @staticmethod
    def get_cert_position(cert: dict) -> float:
        """
        Gets the position of the certificate in the chain.

        Args:
            cert (dict): The certificate to be checked

        Returns:
            float: The position of the certificate in the chain
        """
        # Extract the certificate ID
        cert_id = cert.get('id', '')
        # Check if certificate is leaf
        if cert_id == 'Leaf Certificate':
            return 0
        # Check if certificate is root
        elif cert_id == 'Root CA Certificate':
            return float('inf')
        # Extract number (e.g., Intermediate Certificate #2 → 2)
        match = re.search(r'#(\d+)', cert_id)
        # Return the number found
        return int(match.group(1))

    @staticmethod
    def build_certificate(cert_id: str, cert: str) -> dict:
        """
        Builds the certificate object for the respective chain.

        Args:
            cert_id (str): The certificate ID
            cert (str): The certificate to be validated
        
        Returns:
            dict: The certificate information
        """
        # Create the certificate information object
        cert_data = {
            "id": cert_id,
            "status": "valid",
            "certificate": "",
            "pem": cert
        }
        # Decode the certificate
        cert = Certificate.decode(cert)
        # Add the certificate to the response
        cert_data["certificate"] = cert
        # Initialize certificate status
        cert_data["status"] = "valid"
        # Return the certificate information
        return cert_data

    @staticmethod
    def validate_certificate(domain: str, pos: int, cert: str, cert_chain: list) -> tuple:
        """
        Validate the certificate in the respective chain.

        Args:
            domain (str): The domain to be validated
            pos (int): The position of the certificate in the chain
            cert (str): The certificate to be validated
            cert_chain (list): The certificate chain
        
        Returns:
            dict: The certificate information
            list: The issues found during validation
        """
        # Create the certificate information object
        cert_data = {
            "id": cert['id'],
            "status": "valid",
            "issues": [],
            "warnings": [],
            "certificate": "",
        }
        # Create the issues list
        issues = []
        # Add the certificate to the response
        cert_data["certificate"] = cert
        # Initialize the certificate validation class
        validator = CertificateValidator(cert_chain)
        # Validate the certificate
        status, issues, warnings = validator.validate(domain, pos, cert_data['id'])
        # Check if the certificate status
        if status > 0:
            # Update the certificate status
            cert_data["status"] = "invalid"
        # Add the issues to the response
        cert_data["issues"] = issues
        # Add the issues to the response
        cert_data["warnings"] = warnings
        # Return the certificate information
        return cert_data

    @staticmethod
    def reorder_cert_chain(cert_chain: list) -> list:
        """
        Reorder the certificate chain to ensure the correct order of certificates.

        Args:
            cert_chain (list): The certificate chain to be reordered

        Returns:
            list: The reordered certificate chain
        """
        # Initialize the ordered chain object
        ordered_chain = []
        # Initialize the extra certs object
        extra_certs = []
        # Add the leaf certificate to the ordered chain
        ordered_chain.append(cert_chain[0])
        # Remove leaf certificate from the original chain
        cert_chain = cert_chain[1:]
        # Initialize match flag
        match = True
        # Initialize intermediate counter
        inter = 1
        # Iterate through the remaining certificates
        while match:
            # Get the last certificate in the ordered chain
            last_cert = ordered_chain[-1]
            # Get the issuer of the leaf certificate
            issuer = Certificate.get_issuer(last_cert['pem'])
            # Iterate through the certificates in the chain
            for i, cert in enumerate(cert_chain):
                # Get the issuer of the current certificate
                cert_subject = Certificate.get_subject(cert['pem'])
                # Check if the issuer matches the current issuer
                if cert_subject == issuer:
                    if ChainValidator.is_signed_by(last_cert['pem'], cert['pem']):
                        # Check if certificate is an intermediate
                        if "Intermediate Certificate" in cert['id']:
                            # Update the certificate ID
                            cert['id'] = f"Intermediate Certificate #{inter}"
                            # Increment the intermediate counter
                            inter += 1
                        # Add the certificate to the ordered chain
                        ordered_chain.append(cert)
                        # Remove the certificate from the original chain
                        cert_chain.pop(i)
                        # Update the issuer to the current certificate's subject
                        issuer = Certificate.get_issuer(cert['pem'])
                        break
            match = False
        # Iterate through the remaining certificates in the chain
        for cert in cert_chain:
            # Add them as extra certificates
            extra_certs.append(cert)
        # Check if the last certificate in the ordered chain is an intermediate
        if "Intermediate Certificate" in ordered_chain[-1]['id']:
            # Create the certificate id
            cert_id = "Root CA Certificate"
            # Get the issuer name
            issuer = Certificate.get_issuer(ordered_chain[-1]['pem'])
            # Fetch the root certificate
            root_cert = RootCA.get_certificate(issuer)
            # Partition the root certificate into a list
            root_cert_list = re.findall(
                r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", 
                root_cert,
                re.DOTALL
            )
            # Check if root certificate list is not empty
            if len(root_cert_list) > 0:
                # Iterate through the root certificate list
                for root_cert in root_cert_list:
                    if ChainValidator.is_signed_by(ordered_chain[-1]['pem'], root_cert):
                        # Build and add the root certificate to the chain
                        ordered_chain.append(ChainValidator.build_certificate(cert_id, root_cert))
        # Return the reordered chain
        return ordered_chain, extra_certs

    @staticmethod
    def order_cert_chain(cert_chain: list) -> list:
        """
        Order the certificate chain based on the issuer of each certificate.

        Args:
            cert_chain (list): The certificate chain to be ordered

        Returns:
            list: The ordered certificate chain
        """
        # Initialize the ordered chain object
        ordered_chain = []
        # Fetch the leaf certificate
        leaf_cert = next((cert for cert in cert_chain if cert.get('id') == 'Leaf Certificate'), None)
        # Append the leaf certificate
        ordered_chain.append(leaf_cert)
        cert_chain.remove(leaf_cert)
        # Initialize the target issuer
        target_issuer = leaf_cert['certificate']['issuer']
        # Iterate while len cert_chain > 0
        while len(cert_chain) > 0:
            # Fetch the next certificate that matches the target issuer
            next_cert = next((cert for cert in cert_chain if cert['certificate']['subject'] == target_issuer), None)
            # If no next certificate is found, break the loop
            if next_cert is None:
                break
            # Update the target issuer to the next certificate's subject
            target_issuer = next_cert['certificate']['issuer']
            # Append the next certificate to the ordered chain
            ordered_chain.append(next_cert)
            # Remove the next certificate from the original chain
            cert_chain.remove(next_cert)
        
        # Return the ordered certificate chain
        return ordered_chain

    @staticmethod
    def check_cert_chain(cert_chain: list) -> list:
        """
        Reorder the certificate chain to ensure the correct order of certificates,
        whilst checking if any certificates are missing. Additionally, it checks
        for extra certificates that are not part of the chain or duplicate
        certificates.

        Args:
            cert_chain (list): The certificate chain to be reordered

        Returns:
            list: The reordered certificate chain
            extra_certs (list): The extra certificates that are not part of the chain
            missing (list): The missing certificates that are not part of the chain
        """
        # Initialize the ordered chain object
        ordered_chain = []
        # Initialize the extra certs object
        extra_certs = []
        # Initialize the missing certificates list
        missing = []
        # Add the leaf certificate to the ordered chain
        ordered_chain.append(cert_chain[0])
        # Remove leaf certificate from the original chain
        # cert_chain = cert_chain[1:]

        # Check for duplicate certificates
        clean_chain = set()
        # Iterate through the certificates in the chain
        for cert in cert_chain:
            # Extract the PEM certificate
            cert_pem = cert['pem']
            # Check if the certificate is already seen
            if cert_pem in clean_chain:
                # If it is a duplicate, add it to the extra certificates
                extra_certs.append(cert)
                # Remove certificate from the chain
                cert_chain.remove(cert)
            else:
                clean_chain.add(cert_pem)
        # Delete the clean_chain variable
        del clean_chain

        # Check for missing certificates
        for cert in cert_chain:
            # Check if the certificate is a root CA
            if "Root CA Certificate" in cert['id']:
                # Ignore root CA certificates
                continue
            else:
                # Get the issuer of the certificate
                issuer = Certificate.get_issuer(cert['pem'])
                # Check if the issuer is in the ordered chain
                if not any(issuer == Certificate.get_subject(c['pem']) for c in cert_chain):
                    issuer_cert, trust_store = ChainValidator.fetch_issuer_certificate(cert['pem'])
                    # Add the issuer certificate to the missing list
                    if issuer_cert:
                        # Check if issuer certificate is in trust store
                        if not trust_store:
                            missing.append(issuer)
                        # Convert certificate to PEM format
                        issuer_cert = issuer_cert.public_bytes(serialization.Encoding.PEM).decode()
                        # Check if issuer is root CA
                        if RootCA.check_if_root_ca(issuer_cert):
                            id = "Root CA Certificate"
                        else:
                            id = "Intermediate Certificate"
                        # Build the certificate
                        cert_data = ChainValidator.build_certificate(id, issuer_cert)
                        # Add the certificate to the chain
                        cert_chain.append(cert_data)

        # Reorder the certificate chain
        ordered_chain = ChainValidator.order_cert_chain(cert_chain)

        return ordered_chain, extra_certs, missing

    @staticmethod
    def build_chain_new(cert_chain: list) -> list:
        """
        Build the certificate chain for a given list.

        Args:
            cert_chain (list): The certificate chain to be built

        Returns:
            list: The certificate chain
            extra: The extra certificates that are not part of the chain
            missing: The missing certificates that are not part of the chain
        """
        # Initialize the chain object
        chain = []
        # Iterate through the provided chain
        for i, cert in enumerate(cert_chain):
            if i == 0:
                # Leaf certificate
                cert_id = "Leaf Certificate"
            elif RootCA.check_if_root_ca(cert):
                # Root CA certificate
                cert_id = "Root CA Certificate"
            else:
                # Intermediate certificate
                cert_id = "Intermediate Certificate"
            # Build the certificate
            cert_data = ChainValidator.build_certificate(cert_id, cert)
            # Add certificate to chain
            chain.append(cert_data)
        # Order the certificate chain and check for missing and extra certificates
        chain, extra, missing = ChainValidator.check_cert_chain(chain)
        # Return the response object
        return chain, extra, missing

    @staticmethod
    def build_chain(cert_chain: list) -> list:
        """
        Build the certificate chain for a given list.

        Args:
            cert_chain (list): The certificate chain to be built

        Returns:
            list: The certificate chain
        """
        # Root CA flag
        root_ca_present = False
        # Intermediate counter
        intermediate_counter = 1
        # Initialize the chain object
        chain = []
        # Issuer name (aux)
        issuer = ""
        # Iterate through the provided chain
        for i, cert in enumerate(cert_chain):
            # If the flag is set to True, skip the rest of the certificates
            if root_ca_present:
                continue
            # Check if certificate is a root CA
            if RootCA.check_if_root_ca(cert):
                # Create the id for the root CA
                cert_id = "Root CA Certificate"
                # Set the flag to True
                root_ca_present = True
            else:
                # Create the id for the intermediate and leaf certificates
                if i == 0:
                    # Leaf certificate
                    cert_id = "Leaf Certificate"
                else:
                    # Intermediate certificate
                    cert_id = f"Intermediate Certificate #{intermediate_counter}"
                    # Increment the counter
                    intermediate_counter += 1
            # Build the certificate
            cert_data = ChainValidator.build_certificate(cert_id, cert)
            # Add the certificate object to the response
            chain.append(cert_data)
            # If last cert is an intermediate, try to fetch the root
            if i == len(cert_chain) - 1 and \
                "Intermediate Certificate" in cert_id and \
                    not root_ca_present:
                # Create the certificate id
                cert_id = "Root CA Certificate"
                # Get the issuer name
                issuer = Certificate.get_issuer(cert)
                # Fetch the root certificate
                root_cert = RootCA.get_certificate(issuer)
                # If root certificate is found, add it to the chain
                if root_cert is not None:
                    # Build the certificate
                    root_cert = ChainValidator.build_certificate(cert_id, root_cert)
                    # Add the root certificate to the chain
                    chain.append(root_cert)
        # Sort the certificate chain based on the position of each certificate
        chain.sort(key=lambda x: ChainValidator.get_cert_position(x))
        # Return the response object
        return chain


    @staticmethod
    def validate_chain(domain: str, cert_chain: list, extra_certs: list, missing: list,show_cert: bool) -> dict:
        """
        Validate the certificate chain of a given domain.

        Args:
            cert_chain (list): The certificate chain to be validated
            extra_certs (list): The extra certificates that are not part of the chain
            missing (list): The missing certificates that are not part of the chain
            domain (str): The domain to be validated
            show_cert (bool): Whether to show the certificate fields in the response


        Returns:
            dict: The response object containing the validation
        """
        # Initialize the response object
        response = {
            "domain": domain,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip-address": socket.gethostbyname(domain),
            "status": "valid",
            "analysis": [],
            "chain": []
        }
        # Check if extra certificates are present
        if len(extra_certs) > 0:
            # Add the extra certificates to the response
            response["analysis"].append("Extra certificates were provided.")
        # Check if missing certificates are present
        if len(missing) > 0:
            # Add the missing certificates to the response
            response["analysis"].append("Missing certificates had to be fetched from AIA.")
        # Iterate through the provided chain
        for i, cert in enumerate(cert_chain):
            # Validate the certificate
            cert_data = ChainValidator.validate_certificate(domain, i, cert, cert_chain)
            # Check if the certificate status is invalid
            if cert_data['status'] == "invalid":
                # Update the response status
                response["status"] = "invalid"
            # Add warnings to certificates that were missing
            for missing_cert in missing:
                # Check if the subject string contains the missing issuer
                if missing_cert in cert_data['certificate']['certificate']['subject']:
                    cert_data['warnings'].append(
                        "Certificate was missing and fetched from AIA."
                    )
            # If flag is set to False
            if not show_cert:
                # Remove the certificate from the response
                cert_data.pop("certificate", None)
            # Add the certificate object to the response
            response["chain"].append(cert_data)
        # Return the response object
        return json.dumps(response, indent=4)
