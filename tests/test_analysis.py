"""
This set of tests is made to check if the analysis of the domain
is working and behaving as expected.
"""

import unittest

from certificate_info import CertificateACertificateInformationnalyzer

class TestDomainAnalysis(unittest.TestCase):
    """Test the domain analysis function."""

    def setUp(self):
        self.analyzer = CertificateInformation()

    def test_domains(self):
        """Tests the analysis of a domain."""
        result = self.analyzer.analyze('cm-porto.pt')
        print(result)

if __name__ == '__main__':
    unittest.main()
