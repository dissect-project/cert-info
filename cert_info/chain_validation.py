"""
This module contains all the code required to validate the certificate chain
of a given domain.
"""
import platform
import subprocess
import socket
import json

from cert_info.root_ca_validation import RootCAValidator
from datetime import datetime

from cert_info.certificate import Certificate
from cert_info.certificate_validation import CertificateValidator

class ChainValidator:
    """
    ChainValidator class that provides methods to validate the certificate
    chain of a given domain.
    """

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
        if not status:
            # Update the certificate status
            cert_data["status"] = "invalid"
        # Add the issues to the response
        cert_data["issues"] = issues
        # Add the issues to the response
        cert_data["warnings"] = warnings
        # Return the certificate information
        return cert_data

    @staticmethod
    def build_chain(cert_chain: list) -> list:
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
            # Create the certificate id
            cert_id = "Leaf Certificate" if i == 0 else f"Intermediate Certificate #{i}"
            # Build the certificate
            cert_data = ChainValidator.build_certificate(cert_id, cert)
            # Add the certificate object to the response
            chain.append(cert_data)
            # If last cert is an intermediate, try to fetch the root
            if i == len(cert_chain) - 1 and \
                "Intermediate Certificate" in cert_id:
                # Create the certificate id
                cert_id = "Root CA Certificate"
                # Get the issuer name
                issuer = Certificate.get_issuer(cert)
                # Fetch the root certificate
                root_cert = RootCAValidator.get_certificate(issuer)
                # If root certificate is found, add it to the chain
                if root_cert is not None:
                    # Build the certificate
                    root_cert = ChainValidator.build_certificate(cert_id, root_cert)
                    # Add the root certificate to the chain
                    chain.append(root_cert)
        # Return the response object
        return chain


    @staticmethod
    def validate_chain(domain: str, cert_chain: list) -> dict:
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
        # Iterate through the provided chain
        for i, cert in enumerate(cert_chain):
            # Validate the certificate
            cert_data = ChainValidator.validate_certificate(domain, i, cert, cert_chain)
            # Add the certificate object to the response
            response["chain"].append(cert_data)
        # Return the response object
        return json.dumps(response, indent=4)
