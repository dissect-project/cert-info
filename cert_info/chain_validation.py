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

from cert_info.root_ca import RootCA
from cert_info.certificate import Certificate
from cert_info.certificate_validation import CertificateValidator

class ChainValidator:
    """
    ChainValidator class that provides methods to validate the certificate
    chain of a given domain.
    """

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
    def build_chain_new(cert_chain: list) -> list:
        """
        Build the certificate chain for a given list.

        Args:
            cert_chain (list): The certificate chain to be built

        Returns:
            list: The certificate chain
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
        # Order the certificate chain and check for extra certificates
        chain, extra = ChainValidator.reorder_cert_chain(chain)
        # Return the response object
        return chain, extra

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
    def validate_chain(domain: str, cert_chain: list, extra_certs: list, show_cert: bool) -> dict:
        """
        Validate the certificate chain of a given domain.

        Args:
            cert_chain (list): The certificate chain to be validated

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
        # Iterate through the provided chain
        for i, cert in enumerate(cert_chain):
            # Validate the certificate
            cert_data = ChainValidator.validate_certificate(domain, i, cert, cert_chain)
            # If flag is set to False
            if not show_cert:
                # Remove the certificate from the response
                cert_data.pop("certificate", None)
            # Add the certificate object to the response
            response["chain"].append(cert_data)
        # Return the response object
        return json.dumps(response, indent=4)
