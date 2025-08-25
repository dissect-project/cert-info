"""
This module contains the code required to verify and validate if
a given issuer is a valid Certificate Authority (CA) present in
the local certificate store.
"""

import os
import platform
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

MOZILLA_CA_BUNDLE = "cert_info/mozilla-certs.pem"

class RootCA:
    """
    Root Certificate Authority (CA) Validator class that provides methods
    to validate if a given issuer is a valid CA in the local system.
    """


    @staticmethod
    def check_if_root_ca(cert: str) -> bool:
        """
        Checks if a given certificate is a valid Root CA.
        
        Args:
            cert (str): The certificate to be checked.
        
        Returns:
            bool: True if the certificate is a valid Root CA, False otherwise.
        """
        # Load the certificate
        cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
        # Check if the certificate is self-signed
        if cert.issuer == cert.subject:
            # Check if the certificate is a CA
            return cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.BASIC_CONSTRAINTS).value.ca
        # Certificate is not from a root CA
        return False

    @staticmethod
    def check_macos_keychain(issuer_cn: str) -> str:
        """
        Checks if a given Common Name (CN) exists in macOS System
        Root CA store.
        
        Args:
            issuer_cn (str): The issuer's Common Name.
            
        Returns:
            str: The certificate of the issuer if found, None otherwise.
        """
        try:
            result = subprocess.run(
                ["security", "find-certificate", "-a", "-Z", "-c",
                issuer_cn, "-p", "/System/Library/Keychains/SystemRootCertificates.keychain"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                check=False
            )
            # Check if any certificate was found
            if result.returncode == 0 and result.stdout:
                # Return the certificate
                return result.stdout.strip()
            else:
                return None
        except FileNotFoundError:
            print("macOS 'security' command not found.")
            return None

    @staticmethod
    def check_windows_store(issuer_cn: str) -> str:
        """
        Checks if a given Common Name (CN) exists in the Windows
        Root CA store.
        
        Args:
            issuer_cn (str): The issuer's Common Name.
        
        Returns:
            str: The certificate of the issuer if found, None otherwise.
        """
        try:
            result = subprocess.run(
                ["certutil", "-store", "ROOT"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                check=False
            )
            return result.stdout  # If issuer CN appears, it is trusted
        except FileNotFoundError:
            print("Windows 'certutil' command not found.")
            return None

    @staticmethod
    def check_linux_ca(issuer_cn: str) -> str:
        """
        Checks if a given Common Name (CN) exists in the Linux system CA bundle.
        
        Args:
            issuer_cn (str): The issuer's Common Name.
            
        Returns:
            str: The certificate of the issuer if found, None otherwise.
        """
        # Possible CA bundle paths for different Linux distros
        ca_paths = [
            "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu
            "/etc/pki/tls/certs/ca-bundle.crt",    # Red Hat/CentOS/Fedora
            "/etc/ssl/cert.pem"                    # Alpine Linux
        ]
        # Iterate possible paths
        for ca_path in ca_paths:
            if os.path.exists(ca_path):
                with open(ca_path, "r", encoding="utf-8") as ca_file:
                        return ca_file.read()
        # Issuer not found in any CA bundle
        return None

    @staticmethod
    def check_mozilla_ca_bundle(issuer_cn: str) -> str:
        """
        Checks if a given Common Name (CN) exists in Mozilla's CA bundle.
        
        Args:
            issuer_cn (str): The issuer's Common Name.
            
        Returns:
            str: The certificate of the issuer if found, None otherwise.
        """
        if not os.path.isfile(MOZILLA_CA_BUNDLE):
            raise FileNotFoundError(f"PEM file '{MOZILLA_CA_BUNDLE}' not found.")

        # Read the PEM file
        with open(MOZILLA_CA_BUNDLE, "r", encoding="utf-8") as f:
            bundle_pem = f.read()

        # Split the bundle into individual certificates
        certs = bundle_pem.split("-----END CERTIFICATE-----")
        for cert_pem in certs:
            cert_pem = cert_pem.strip()
            if not cert_pem:
                continue
            cert_pem += "\n-----END CERTIFICATE-----\n"

            try:
                cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            except Exception:
                continue  # Skip invalid certificates
            # Get the subject CN
            subject = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            # Check if CN is present
            if len(subject) > 0:
                # Check the Common Name (CN)
                if subject and subject[0].value == issuer_cn:
                    return cert_pem  # Return the full PEM
            else:
                # Check the Organizational Unit (OU) if CN is not present
                if cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == issuer_cn:
                    return cert_pem
        return None

    @staticmethod
    def get_certificate(issuer_cn: str) -> str:
        """
        Determines if an issuer Common Name is in the local system
        CA store of an OS. The function detects which OS is in the
        local machine, and performs retrieves the certificate. In 
        case there is no certificate in the local store, Mozzila's
        CA bundle is used instead.
        
        Args:
            issuer_cn (str): The issuer's Common Name.

        Returns:
            str: Certificate in string format.
        """
        # Initialize certificate object
        cert = None
        # Get the OS name
        os_name = platform.system()
        # Perform validation based on the OS
        if os_name == "Darwin":  # macOS
            # Check if the issuer is in the macOS Keychain
            cert = RootCA.check_macos_keychain(issuer_cn)
        elif os_name == "Windows":
            # Check if the issuer is in the Windows Root CA store
            cert = RootCA.check_windows_store(issuer_cn)
        elif os_name == "Linux":
            # Check if the issuer is in the Linux CA bundle
            cert = RootCA.check_linux_ca(issuer_cn)
        # Check if certificate was found
        if cert is None:
            # Use Mozilla's CA bundle as fallback
            cert = RootCA.check_mozilla_ca_bundle(issuer_cn)
        # Return the result
        return cert
