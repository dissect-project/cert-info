"""
Command line utility script. This script allows the cert_info module to
be used through the command line. Consumes a single argument, which is 
the domain name, and returns a response to the terminal.
"""

import argparse

from cert_info import CertificateInformation
import os
import json


def main():
    """
    Main function to execute the utility script.
    """
    # Capture command-line arguments
    parser = argparse.ArgumentParser(
        prog="cert-info",
        description="Verify the certificate chain of a given domain.",
        epilog="Part of the DISSECT Project."
    )
    # Add an argument for the domain name
    parser.add_argument("-d", "--domain", required=True, help="The domain to be analyzed.")
    parser.add_argument("--show-cert", action="store_true", help="Output certificate fields in the response.")
    parser.add_argument("--output", action="store_true", help="Write output into default data directory.")
    parser.add_argument("--output-path", help="Write output to a specific path.")
    parser.add_argument(
        "-f", "--force", action="store_true", help="Force the analysis even if the domain is not reachable."
    )
    # Parse the command-line arguments
    args = parser.parse_args()
    # Initialize the CertificateInformation class
    cert_info = CertificateInformation()
    # Run the analysis
    result = cert_info.analyze(args.domain, args.show_cert, args.force)
    # If output is requested, write the result to the default data directory
    if args.output:
        # If a specific output path is provided, use it
        if args.output_path:
            data_dir = args.output_path
            # Ensure the directory exists
            os.makedirs(os.path.dirname(data_dir), exist_ok=True)
        else:
            # Build the path to the data directory 
            data_dir = os.path.join(os.path.dirname(__file__), "data")
            # Ensure the directory exists
            os.makedirs(data_dir, exist_ok=True)
        # Build the output file path
        output_path = os.path.join(data_dir, f"{args.domain}.json")
        # Write the result to the output file
        with open(output_path, "w", encoding="utf-8") as f:
            if isinstance(result, dict):
                # Convert the result to a JSON string
                result = json.dumps(result, indent=4)
            f.write(result)
    # Print the result in JSON format
    print(result)


if __name__ == "__main__":
    main()
