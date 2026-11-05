"""
This set of tests is made to check if the validity and the reachability of the domain
is being accurately assessed by the analyzer.
"""

import unittest

from src.certificate_info import CertificateInformation
from src.fetch.domain import split_host_port
from src.fetch.https_probe import host_port_from_url

class TestDomainValidation(unittest.TestCase):
    """Test the domain validation functions."""

    def setUp(self):
        self.analyzer = CertificateInformation()

    def test_valid_domains(self):
        """Tests the validation of valid domain formats."""
        # Examples of valid domains
        self.assertTrue(self.analyzer.is_valid('www.random-domain.com'))
        self.assertTrue(self.analyzer.is_valid('https://www.random-domain.com'))
        self.assertTrue(self.analyzer.is_valid('www.random-domain.com'))

    def test_valid_uncommon_domains(self):
        """Long and internationalised TLDs and underscores used to be rejected."""
        for domain in ('example.photography', 'example.international', 'example.xn--p1ai',
                       'xn--80ak6aa92e.com', 'my_host.example.com', 'example.com:8443'):
            with self.subTest(domain=domain):
                self.assertTrue(self.analyzer.is_valid(domain))

    def test_invalid_domains(self):
        """Tests the validation of invalid domain formats."""
        # Examples of invalid domains
        self.assertFalse(self.analyzer.is_valid('www.random-domain.c'))
        self.assertFalse(self.analyzer.is_valid('www.random-domain'))
        self.assertFalse(self.analyzer.is_valid('htt://www.random-domain.com'))

    def test_reachable_domains(self):
        """Tests if domains are reachable."""
        # Examples of valid domains
        self.assertTrue(self.analyzer.is_reachable('www.google.com'))
        self.assertTrue(self.analyzer.is_valid('https://github.com'))

    def test_unreachable_domains(self):
        """Tests if domains are unreachable."""
        # Examples of valid domains
        self.assertFalse(self.analyzer.is_reachable('www.github.co'))
        self.assertFalse(self.analyzer.is_reachable('www.goooogle.pt'))

class TestHostAndPort(unittest.TestCase):
    """The requested port is kept instead of always using 443."""

    def testsplit_host_port(self):
        self.assertEqual(split_host_port('example.com'), ('example.com', 443))
        self.assertEqual(split_host_port('example.com:8443'), ('example.com', 8443))
        self.assertEqual(split_host_port('https://example.com:8443'), ('example.com', 8443))
        self.assertEqual(split_host_port('http://example.com'), ('example.com', 443))
        self.assertEqual(split_host_port('example.com:0'), ('example.com', None))
        self.assertEqual(split_host_port('example.com:70000'), ('example.com', None))

    def test_host_port_from_redirect(self):
        self.assertEqual(host_port_from_url('https://www.example.com/', 'example.com', 443),
                         ('www.example.com', 443))
        self.assertEqual(host_port_from_url('https://example.com:8443/x', 'example.com', 443),
                         ('example.com', 8443))
        self.assertEqual(host_port_from_url('http://example.com/', 'example.com', 8443),
                         ('example.com', 443))


if __name__ == '__main__':
    unittest.main()
