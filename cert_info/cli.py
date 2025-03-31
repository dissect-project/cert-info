"""
Command line utility script. This script allows the cert_info module to
be used through the command line. Consumes a single argument, which is 
the domain name, and returns a response to the terminal.
"""

import argparse

from cert_info import CertificateInformation


def main():
    """
    Main function to execute the utility script.
    """
    # Capture command-line arguments
    parser = argparse.ArgumentParser(description="Verify the certificate chain of a given domain.")
    # Add an argument for the domain name
    parser.add_argument("-d", "--domain", required=True, help="The domain to be analyzed.")
    # Parse the command-line arguments
    args = parser.parse_args()
    # Initialize the CertificateInformation class
    cert_info = CertificateInformation()
    # Run the analysis
    result = cert_info.analyze(args.domain)
    # Print the result in JSON format
    print(result)


if __name__ == "__main__":
    main()
