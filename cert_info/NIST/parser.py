"""
This module serves as a parser for the recommendations provided by the NCSC
for the use of cryptographic algorithms. It allows to map data from the csv
files into usable structures for the evaluation of the certificates.
"""

import csv
import re
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa, ed25519, ed448

# Define the path to the CSV files
PATH = "cert_info/NIST/"

class CSVParser:
    """
        This class is responsible for parsing CSV files containing
        cryptographic algorithm recommendations from NIST. It 
        provides methods to verify the status of hash functions,
        algorithms, or key sizes
    """

    @staticmethod
    def __verify_curve(curve: str, csv_file: str = "curves.csv") -> str:
        """
        Verifies wether the given curve is sacceptable or not according
        to NITS's guidelines.

        Args:
            curve (str): The curve to be checked.
            csv_file (str): The path to the CSV file containing the
                            NIST recommendations.

        Returns:
            str: The status of the curve (e.g., "Deprecated", "Acceptable").
        """
        # Read the CSV file
        with open(PATH + csv_file, newline='', encoding='utf-8') as csvfile:
            # Create a CSV reader
            reader = csv.DictReader(csvfile)
            # Iterate through each row in the CSV file
            for row in reader:
                # Get the curve name and status
                name = row["Curve"].strip().upper()
                status = row["Status"].strip()
                # Check if the curve mathces
                if name == curve.upper():
                    # Return the status for the curve
                    return status
        # If the curve is not found in the mapping, return an error
        raise ValueError(f"Unsupported curve: {curve}")


    @staticmethod
    def __verify_range(number: int, range_condition: str) -> bool:
        """
        Verifies whether the given number matches the condition in the
        range present in the CSV files.

        Args:
            number (int): The number to be checked.
            range_condition (str): The condition to check against.

        Returns:
            bool: True if the number matches the condition, False otherwise.
        """
        # Split the condition into operator and value (e.g., "<", "224" or ">=", "224")
        operator, value = range_condition.split()
        # Convert the value to an integer for comparison
        value = int(value)
        # Check the operator and perform the comparison
        if operator == "<":
            return number < value
        elif operator == "<=":
            return number <= value
        elif operator == ">":
            return number > value
        elif operator == ">=":
            return number >= value
        else:
            # Raise an error if the operator is not recognized
            raise ValueError(f"Unsupported operator: {operator}")

    @staticmethod
    def get_hash_status(hash_function, csv_file: str = "hash_functions.csv") -> str:
        """
        Verifies whether the hash functions are considered secure or not
        using the NIST recommendations provided in the CSV file.

        Args:
            hash_function (str): The hash function to be checked.
            csv_file (str): The path to the CSV file containing the
                            NIST recommendations.

        Returns:
            str: The status of the hash function (e.g., "good", "insufficient").
        """
        # Map string names to hash
        name_to_hash = {
            "MD5": hashes.MD5,
            "SHA-1": hashes.SHA1,
            "SHA-224": hashes.SHA224,
            "SHA-256": hashes.SHA256,
            "SHA-384": hashes.SHA384,
            "SHA-512": hashes.SHA512,
            "SHA-512/224": hashes.SHA512_224,
            "SHA-512/256": hashes.SHA512_256,
            "SHA3-224": hashes.SHA3_224,
            "SHA3-256": hashes.SHA3_256,
            "SHA3-384": hashes.SHA3_384,
            "SHA3-512": hashes.SHA3_512,
        }
        # Reverse map: hash to string name
        hash_to_name = {cls: name for name, cls in name_to_hash.items()}
        # Map string name to status from CSV
        name_to_status = {}
        # Read the CSV file
        with open(PATH + csv_file, newline='', encoding='utf-8') as csvfile:
            # Create a CSV reader
            reader = csv.DictReader(csvfile)
            # Iterate through each row in the CSV file
            for row in reader:
                # Get the algorithm name and status
                name = row["Algorithm"].strip().upper()
                status = row["Status"].strip()
                # Get the corresponding hash status
                name_to_status[name] = status
        # Check if the hash function is in the mapping
        for cls, name in hash_to_name.items():
            # Check if the hash function matches the class
            if isinstance(hash_function, cls):
                # Retrieve the name of the hash function
                status = name_to_status.get(name.upper())
                # If the hash function is found in the mapping
                if status:
                    # Return the name and status
                    return status
        # If the hash function is not found in the mapping, return an error
        raise ValueError(f"Unsupported hash function: {hash_function}")

    @staticmethod
    def get_key_status(public_key, csv_file: str = "algorithms_key_lengths.csv") -> str:
        """
        Verifies wether the public key in the certificate is considered secure or not
        using the NIST recommendations provided in the CSV file.

        Args:
            public_key (str): The public_key to be checked.
            csv_file (str): The path to the CSV file containing the
                            NIST recommendations.

        Returns:
            str: The status of the hash function (e.g., "good", "insufficient").
        """
        # Map string name to status and key length from CSV
        name_to_status_and_length = {}
        # Initialize list of issues
        issues = []
        # Read the CSV file
        with open(PATH + csv_file, newline='', encoding='utf-8') as csvfile:
            # Create a CSV reader
            reader = csv.DictReader(csvfile)
            # Iterate through each row in the CSV file
            for row in reader:
                # Get the algorithm name and status
                name = row["Algorithm"].strip().upper()
                klength = row["Key Length"].strip()
                status = row["Status"].strip()
                # Check if the algorithm already exists in the dictionary
                if name not in name_to_status_and_length:
                    # If it doesn't exist, initialize it with an empty list
                    name_to_status_and_length[name] = []
                # Append the new status and key length as a dictionary
                name_to_status_and_length[name].append({"range": klength, "status": status})
        # Initialize the validations variable
        validations = None
        # Check if key is DSA
        if isinstance(public_key, dsa.DSAPublicKey):
            # Retrieve the validations for the key type
            validations = name_to_status_and_length.get("DSA")
        # Check if key is ECDSA
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            # Retrieve the validations for the key type
            validations = name_to_status_and_length.get("ECDSA")
            # Check if the curve is acceptable
            curve_status = CSVParser.__verify_curve(public_key.curve.name)
            # Check if the curve is acceptable
            if curve_status != "Acceptable":
                # Append the curve status to the issues list
                issues.append(f"Usage of curve {curve_status} is {curve_status}")
        # Check if key is RSA
        if isinstance(public_key, rsa.RSAPublicKey):
            # Retrieve the validations for the key type
            validations = name_to_status_and_length.get("RSA")
        # Check if key is ED25519
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            # Retrieve the validations for the key type
            validations = name_to_status_and_length.get("EdDSA")
        # Check if key is ED448
        if isinstance(public_key, ed448.Ed448PublicKey):
            # Retrieve the validations for the key type
            validations = name_to_status_and_length.get("EdDSA")
        # Check if validationf were found for key type
        if validations is None:
            # Raise an error if the key type is not supported
            raise ValueError(f"Unsupported Key: {public_key}")
        # Iterate validations to find the one that matches the key length
        for validation in validations:
            # Extract key length
            key_length = public_key.key_size
            # Check if the key length is in the range
            if CSVParser.__verify_range(key_length, validation["range"]):
                # If the key length is found, retrieve the status
                status = validation["status"]
                # Return the name and status
                return status, issues
        # If the hash function is not found in the mapping, return an error
        raise ValueError(f"Unsupported Key: {public_key}")
