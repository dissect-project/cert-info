"""
This module provides the function required to analyze the digital certificates
of a given domain, returning the results in json format.
"""

import re
import requests
import socket
from OpenSSL import SSL
from cryptography.hazmat.primitives import serialization

from src.chain_validation import ChainValidator

class CertificateInformation:
    """Analyze digital certificates for a given domain."""
    def __init__(self, prefix=False):
        self.prefix = prefix

    def get_pem_cert_from_crtsh(self, domain: str) -> list:
        """
        Retrieve the PEM-encoded certificate for a given domain from crt.sh.
        
        :param domain: The domain name to query certificates for
        :type domain: str

        :return: The PEM-encoded certificate in a list
        """
        # Build the crt.sh query URL and make the request
        url = f"https://crt.sh/?q={domain}&output=json"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        # List to hold PEM certificate
        certs = []
        # Check if response has content
        if len(response.content) > 0:
            # Get the first entry (most recent certificate)
            entry = response.json()[0]
            # Extract the identifier for the certificate
            id = entry.get("id")
            # Build the download endpoint URL
            download_url = f"https://crt.sh/?d={id}"
            # Download the certificate
            download_response = requests.get(download_url, timeout=10)
            download_response.raise_for_status()
            download_data = download_response.content
            certs.append(download_data.decode())
        # Return the list
        return certs

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
            headers = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) \
                AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'
            }
            response = requests.get(domain, timeout=60, headers=headers)
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
        context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)
        conn = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        conn.set_tlsext_host_name(domain.encode())
        conn.connect((domain, port))
        conn.set_connect_state()
        try:
            conn.do_handshake()
        except SSL.Error as e:
            # Try fallback to CT logs
            try:
                cert_chain = self.get_pem_cert_from_crtsh(domain)
                return cert_chain
            except Exception:
                pass
            # Most common case for "Unexpected EOF"
            return {
                "error": f"TLS handshake failed: {e.__class__.__name__}: {e}"
            }
        except Exception as e:
            # Try fallback to CT logs
            try:
                cert_chain = self.get_pem_cert_from_crtsh(domain)
                return cert_chain
            except Exception:
                pass
            return {
                "error": f"Socket error during handshake: {e}"
            }
        # Retrieve the full certificate chain
        cert_chain = []
        for cert in conn.get_peer_cert_chain():
            pem_cert = cert.to_cryptography().public_bytes(serialization.Encoding.PEM)
            cert_chain.append(pem_cert.decode())
        # Close the connection
        conn.close()
        # Return the certificate chain
        return cert_chain

    def analyze(self, domain, show_cert=False, force=False):
        """"
        Analyze the digital certificates of a given domain.

        Args:
            domain (str): The domain to be analyzed.
            show_cert (bool): Whether to show the certificate fields in the response.
            force (bool): Whether to force the analysis even if the domain is not reachable.
        """
        # Check if the domain is valid
        if not self.is_valid(domain):
            return self.__build_error_message("Invalid domain.")
        # Check if the domain is reachable
        if not self.is_reachable(domain) and not force:
            return self.__build_error_message("Domain is not reachable.")
        try:
            # Retrieve the certificate chain from the domain server
            cert_chain = self.__get_certificate_chain(domain)
            # Build the certificate chain object
            cert_chain, extra_certs, missing = ChainValidator.build_chain_new(cert_chain)
            # Analyze the certificate chain
            result = ChainValidator.validate_chain(domain, cert_chain, extra_certs, missing, show_cert)
            # Return a structure with the analysis
            return result
        except KeyboardInterrupt:
            return self.__build_error_message("Scan interrupted.")
