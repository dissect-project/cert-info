"""
This module provides the function required to analyze the digital certificates
of a given domain, returning the results in json format.
"""

import re
import requests
import socket
from OpenSSL import SSL
from cryptography.hazmat.primitives import serialization

from cert_info.chain_validation import ChainValidator

class CertificateInformation:
    """Analyze digital certificates for a given domain."""
    def __init__(self, prefix=False):
        self.prefix = prefix

    def is_valid(self, domain):
        """
        Checks if a domain is valid or not.

        Args:
            domain (str): The domain to be checked.

        Returns:
            bool: True if the domain is valid, False otherwise.
        """
        # Regular expression to match a valid domain
        pattern = re.compile(
            r"^((?:http|https):\/\/)?(?:www\.)?([a-zA-Z0-9.-]+)\.([a-zA-Z]{2,10}$)"
        )
        # Return the result of the match
        return pattern.match(domain) is not  None

    def is_reachable(self, domain):
        """
        Checks if a domain is reachable or not.

        Args:
            domain (str): The domain to be checked.

        Returns:
            bool: True if the domain is reachable, False otherwise.
        """
        try:
            # Add the prefix https:// if not included
            if not domain.startswith('https'):
                domain = f'https://{domain}'
            # Try to connect to the domain
            response = requests.get(domain, timeout=60)
            # Return True if the connection was successful
            return response.status_code == 200
        except requests.exceptions.RequestException:
            # Return False if the connection was not successful
            return False

    def __build_error_message(self, message):
        """
        Build an error message.

        Args:
            message (str): The message to be included in the error message.

        Returns:
            dict: The error message.
        """
        # Build the message
        message = {
            "status": "error",
            "error": message
        }
        # Return the error message
        return message

    def __get_certificate_chain(self, domain, port=443) -> list:
        """
        Retrieve the certificate chain for a given domain.

        Args:
            domain (str): The domain to retrieve the certificate chain.
            port (int): The port to connect to.

        Returns:
            list: The certificate chain.
        """
        # Retrieve the certificate chain using OpenSSL
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        conn = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        conn.set_tlsext_host_name(domain.encode())
        conn.connect((domain, port))
        conn.do_handshake()
        # Retrieve the full certificate chain
        cert_chain = []
        for cert in conn.get_peer_cert_chain():
            pem_cert = cert.to_cryptography().public_bytes(serialization.Encoding.PEM)
            cert_chain.append(pem_cert.decode())
        # Close the connection
        conn.close()
        # Return the certificate chain
        return cert_chain

    def analyze(self, domain):
        """"
        Analyze the digital certificates of a given domain.

        Args:
            domain (str): The domain to be analyzed.
        """
        # Check if the domain is valid
        if not self.is_valid(domain):
            return self.__build_error_message("Invalid domain.")
        # Check if the domain is reachable
        if not self.is_reachable(domain):
            return self.__build_error_message("Domain is not reachable.")
        try:
            # Retrieve the certificate chain from the domain server
            cert_chain = self.__get_certificate_chain(domain)
            # Build the certificate chain object
            cert_chain = ChainValidator.build_chain(cert_chain)
            # Analyze the certificate chain
            result = ChainValidator.validate_chain(domain, cert_chain)
            # Return a structure with the analysis
            return result
        except KeyboardInterrupt:
            return self.__build_error_message("Scan interrupted.")
