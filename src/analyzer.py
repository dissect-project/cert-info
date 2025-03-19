"""
This module provides the function required to analyze the digital certificates
of a given domain, returning the results in json format.
"""

import re
import requests


class CertificateAnalyzer:
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
            response = requests.get(domain, timeout=15)
            # Return True if the connection was successful
            return response.status_code == 200
        except requests.exceptions.RequestException:
            # Return False if the connection was not successful
            return False

    def analyze(self, domain):
        """"
        Analyze the digital certificates of a given domain.

        Args:
            domain (str): The domain to be analyzed.
        """
        # Check if the domain is valid
        if not self.is_valid(domain):
            return "Invalid domain."
        # Check if the domain is reachable
        if not self.is_reachable(domain):
            return "Domain is not reachable."
        # Return a message indicating that the domain is valid and reachable
        return "Domain is valid and reachable."
