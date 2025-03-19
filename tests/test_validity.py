"""
This set of tests is made to check if the validity and the reachability of the domain
is being accurately assessed by the analyzer.
"""

import unittest

from src.analyzer import CertificateAnalyzer

class TestDomainValidation(unittest.TestCase):
    """Test the domain validation functions."""

    def setUp(self):
        self.analyzer = CertificateAnalyzer()

    def test_valid_domains(self):
        """Tests the validation of valid domain formats."""
        # Examples of valid domains
        self.assertTrue(self.analyzer.is_valid('www.random-domain.com'))
        self.assertTrue(self.analyzer.is_valid('https://www.random-domain.com'))
        self.assertTrue(self.analyzer.is_valid('www.random-domain.com'))

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

if __name__ == '__main__':
    unittest.main()
