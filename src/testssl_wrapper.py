"""
This module provides the a wrapper for testssl.sh,
"""

import subprocess
import os
import json

from datetime import datetime

class TestSSL:
    """
    Wrapper for testssl.sh.
    """
    def __init__(self):
        """Initialize with the path to testssl.sh"""
        # Initialize the path to the script directory
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        # Initialize the json directory
        self.json_dir = os.path.join(self.script_dir, "output")
        # Ensure the log directory exists
        os.makedirs(self.json_dir, exist_ok=True)
        # Initialize the path to the testssl.sh script
        self.testssl_path = os.path.join(self.script_dir, "testssl", "testssl.sh")
        # Flags for certificate information and CRL/OCSP checks
        self.flags = "-S --phone-out --hints"
        # Verify wether the testssl.sh path exists
        if not os.path.exists(self.testssl_path):
            raise FileNotFoundError(f"Bundled testssl.sh not found at {self.testssl_path}")

    def __remove_output(self, json_path):
        """
        Remove the output json file.

        Args:
            json_path (str): The path to the json file.
        """
        # Remove the json file
        os.remove(json_path)

    def __get_finding(self, server_defaults, id):
        """
        Get the finding with the specified id.

        Args:
            serverDefaults (list): The serverDefaults list.
            id (str): The id of the finding to retrieve.

        Returns:
            str: The finding for the specified id.
        """
        # Iterate over the findings
        for entry in server_defaults:
            # Return the finding if the id matches
            if entry["id"] == id:
                return entry["finding"]
        # Return None if the finding was not found
        return "not present"

    def __get_server_certificate_info(self, server_defaults):
        """
        Get the server certificate information.

        Args:
            server_defaults (dict): The serverDefaults dictionary.

        Returns:
            dict: The server certificate information.
        """
        # Initialize the certificate information
        info = {}
        # Retieve data
        info["common_name"] = self.__get_finding(server_defaults, "cert_commonName")
        info["alt_names"] = self.__get_finding(server_defaults, "cert_subjectAltName")
        info["serial_number"] = self.__get_finding(server_defaults, "cert_serialNumber")
        info["fingerprint_SHA256"] = self.__get_finding(server_defaults, "cert_fingerprintSHA256")
        info["ca_issuers"] = self.__get_finding(server_defaults, "cert_caIssuers")
        info["list_ordering_problem"] = self.__get_finding(server_defaults, "certs_list_ordering_problem")

        # Retrieve the expiration information
        info["expiration_info"] = {}
        info["expiration_info"]["not_before"] = self.__get_finding(server_defaults, "cert_notBefore")
        info["expiration_info"]["not_after"] = self.__get_finding(server_defaults, "cert_notAfter")
        info["expiration_info"]["expiration"] = self.__get_finding(server_defaults, "cert_expirationStatus")

        # Retrieve the expiration information
        info["signature_info"] = {}
        info["signature_info"]["signature_algorithm"] = self.__get_finding(server_defaults, "cert_signatureAlgorithm")
        info["signature_info"]["key_size"] = self.__get_finding(server_defaults, "cert_keySize")
        info["signature_info"]["key_usage"] = self.__get_finding(server_defaults, "cert_keyUsage")
        info["signature_info"]["ext_key_usage"] = self.__get_finding(server_defaults, "cert_extKeyUsage")

        # Retrieve trust information
        info["trust_info"] = {}
        info["trust_info"]["cert_trust"] = self.__get_finding(server_defaults, "cert_trust")
        info["trust_info"]["cert_trust_wildcard"] = self.__get_finding(server_defaults, "cert_trust_wildcard")
        info["trust_info"]["trust_wildcard"] = self.__get_finding(server_defaults, "cert_trust_wildcard")

        # Retrieve the revocation information
        info["revocation_info"] = {}
        info["revocation_info"]["crl_distribution_points"] = self.__get_finding(server_defaults, "cert_crlDistributionPoints")
        info["revocation_info"]["crl_revoked"] = self.__get_finding(server_defaults, "cert_crlRevoked")
        info["revocation_info"]["ocsp_urls"] = self.__get_finding(server_defaults, "cert_ocspURL")
        info["revocation_info"]["ocsp_revoked"] = self.__get_finding(server_defaults, "cert_ocspRevoked")
        info["revocation_info"]["ocsp_stapling"] = self.__get_finding(server_defaults, "OCSP_stapling")

        # Retrieve the raw certificate
        info["cert"] = self.__get_finding(server_defaults, "cert")

        # Return the certificate information
        return info

    def __parse_results(self, json_data):
        """
        Parse the results from the json data.

        Args:
            json_data (dict): The json data.

        Returns:
            dict: The parsed results.
        """
        # Initialize the results dictionary
        results = {}
        # Get the serverDefaults objetc
        server_defaults = json_data["scanResult"][0]["serverDefaults"]
        # Get the server certificate information
        server_certs = []
        # Iterate over the server certificates
        cert_numbers = int(self.__get_finding(server_defaults, "cert_numbers"))
        for _ in range(1, cert_numbers + 1):
            # Retrieve the certificate information
            info = self.__get_server_certificate_info(server_defaults)
            # Append the certificate information
            server_certs.append(info)
        results["serverCerts"] = server_certs
        # Get the intermediate certificates information
        intermediate_certs = []
        results["intermediateCerts"] = intermediate_certs
        # Return the results
        return results

    def __build_output(self, target, json_file):
        """
        Build the output string from the json file.

        Args:
            target (str): The target that was scanned.
            json_file (str): The path to the json file.

        Returns:
            str: The output string.
        """
        # Initialize the output dic
        output = {
            "target": target,
            "ip": "",
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "result": []
        }
        # Read the json file
        with open(json_file, "r", encoding="utf-8") as file:
            # Load the json data
            data = file.read()
            # Parse the json data
            json_data = json.loads(data)
            # Get the ip address
            output["ip"] = json_data["scanResult"][0]["ip"]
            # Parse the results
            result = self.__parse_results(json_data)
            # Add results to the output
            output["result"].append(result)
        # Remove the json file
        # self.__remove_output(json_file)
        # Return the output
        return json.dumps(output, indent=4)


    def scan(self, target):
        """
        Performs a scan using testssl.sh on the specified target.

        Args:
            target (str): The target to scan.

        Returns:
            dict: The results of the scan.
        """
        # Set environment variables before executing testssl.sh
        env_vars = {
            "MAX_SOCKET_FAIL": "5",
            "MAX_OSSL_FAIL": "5",
            **os.environ  # Keep existing environment variables
        }
        # Get current timestamp
        timestamp = int(round(datetime.now().timestamp()))
        # Build the log and json file paths
        json_file = os.path.join(self.json_dir, f"{timestamp}-{target.replace('.', '-')}.json")
        # Build the output flag
        output = f"--jsonfile-pretty {json_file}"
        # Build the command to run testssl.sh
        command = f"bash {self.testssl_path} {self.flags} {output} {target}"
        try:
            # Run the command
            process = subprocess.run(command, shell=True, capture_output=True,
                                     text=True, env=env_vars, check=False)
            # Raise an exception if the process failed
            if process.returncode != 1:
                raise RuntimeError(f"Error running testssl.sh: {process.stderr}")
            # Return the dictionary with the results
            return self.__build_output(target, json_file)
        except KeyboardInterrupt as kb:
            # Remove the json file
            self.__remove_output(json_file)
            # Raise the KeyboardInterrupt
            raise kb
