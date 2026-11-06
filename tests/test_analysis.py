"""
This set of tests is made to check if the analysis of the domain
is working and behaving as expected.
"""

import os
import unittest

from src.certificate_info import CertificateInformation

NETWORK = os.environ.get("CERTINFO_NETWORK_TESTS", "1") != "0"


@unittest.skipUnless(NETWORK, "needs network access (skipped because CERTINFO_NETWORK_TESTS=0)")
class TestDomainAnalysis(unittest.TestCase):
    """Test the domain analysis function."""

    def setUp(self):
        self.analyzer = CertificateInformation()

    def test_domains(self):
        """Tests the analysis of a domain."""
        result = self.analyzer.analyze('cm-porto.pt')
        self.assertIn(result["status"], ("valid", "invalid"))
        self.assertEqual(result["chain"][0]["id"], "Leaf Certificate")

if __name__ == '__main__':
    unittest.main()
