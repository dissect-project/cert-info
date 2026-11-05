"""
Reads the NIST recommendations on cryptographic algorithms (SP 800-131A and
SP 800-186) from the CSV files in this folder and classifies the hash
functions, public keys and elliptic curves used in certificates.

Statuses, from best to worst:
    Acceptable  may be used
    Deprecated  may be used, but the user must accept security risks
    Legacy      may only be used to process already protected information
                (e.g. verify), not to sign
    Disallowed  may no longer be used to apply cryptographic protection
"""

import csv
import os
from functools import lru_cache

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ACCEPTABLE = "Acceptable"
# Statuses ordered from best to worst
SEVERITY = {ACCEPTABLE: 0, "Deprecated": 1, "Legacy": 2, "Disallowed": 3}

# Hash classes -> names used in hash_functions.csv
HASH_NAMES = {
    hashes.MD5: "MD5",
    hashes.SHA1: "SHA-1",
    hashes.SHA224: "SHA-224",
    hashes.SHA256: "SHA-256",
    hashes.SHA384: "SHA-384",
    hashes.SHA512: "SHA-512",
    hashes.SHA512_224: "SHA-512/224",
    hashes.SHA512_256: "SHA-512/256",
    hashes.SHA3_224: "SHA3-224",
    hashes.SHA3_256: "SHA3-256",
    hashes.SHA3_384: "SHA3-384",
    hashes.SHA3_512: "SHA3-512",
}

# EdDSA keys: (algorithm in algorithms_key_lengths.csv, curve in curves.csv,
# size in bits). The size is that of the public key; NIST's requirement
# (len(n) >= 256) is met by both curves.
EDDSA_KEYS = {
    ed25519.Ed25519PublicKey: ("EdDSA", "ed25519", 256),
    ed448.Ed448PublicKey: ("EdDSA", "ed448", 456),
}


def _read_csv(filename: str) -> list:
    """Rows of a CSV file in this folder, as dicts with stripped values."""
    with open(os.path.join(BASE_DIR, filename), newline="", encoding="utf-8") as csv_file:
        return [{key: (value or "").strip() for key, value in row.items()}
                for row in csv.DictReader(csv_file)]


@lru_cache(maxsize=None)
def _hash_statuses() -> dict:
    """Hash name (upper case) -> status."""
    return {row["Algorithm"].upper(): row["Status"] for row in _read_csv("hash_functions.csv")}


@lru_cache(maxsize=None)
def _curve_statuses() -> dict:
    """Curve name (lower case) -> status."""
    return {row["Curve"].lower(): row["Status"] for row in _read_csv("curves.csv")}


@lru_cache(maxsize=None)
def _key_length_rules() -> dict:
    """Algorithm name (upper case) -> list of (key length condition, status)."""
    rules = {}
    for row in _read_csv("algorithms_key_lengths.csv"):
        rules.setdefault(row["Algorithm"].upper(), []).append((row["Key Length"], row["Status"]))
    return rules


def _matches(key_size: int, condition: str) -> bool:
    """
    Check a key size against a condition such as "< 2048" or ">= 224".
    An empty condition matches every size.
    """
    if not condition:
        return True
    operator, value = condition.split()
    value = int(value)
    comparisons = {
        "<": key_size < value,
        "<=": key_size <= value,
        ">": key_size > value,
        ">=": key_size >= value,
    }
    if operator not in comparisons:
        raise ValueError(f"Unsupported operator: {operator}")
    return comparisons[operator]


def _worst(*statuses: str) -> str:
    """The most severe of several statuses."""
    return max(statuses, key=lambda status: SEVERITY.get(status, 0))


class CSVParser:
    """Classify hash functions, public keys and curves according to NIST."""

    @staticmethod
    def get_hash_status(hash_function: hashes.HashAlgorithm) -> str:
        """
        Status of the hash function used in a signature.

        Args:
            hash_function (hashes.HashAlgorithm): The hash, e.g.
                cert.signature_hash_algorithm.

        Returns:
            str: The status from hash_functions.csv.

        Raises:
            ValueError: If the hash function is not in the table.
        """
        name = HASH_NAMES.get(type(hash_function))
        status = _hash_statuses().get(name.upper()) if name else None
        if status is None:
            raise ValueError(f"Unsupported hash function: {hash_function}")
        return status

    @staticmethod
    def get_curve_status(curve_name: str) -> str:
        """
        Status of an elliptic curve (e.g. "secp256r1", "ed25519").

        Raises:
            ValueError: If the curve is not in curves.csv.
        """
        status = _curve_statuses().get(curve_name.lower())
        if status is None:
            raise ValueError(f"Unsupported curve: {curve_name}")
        return status

    @staticmethod
    def get_key_status(public_key) -> tuple[str, list]:
        """
        Status of a public key, from its algorithm and size and, for elliptic
        curve keys, its curve. The worst of the two statuses is returned.

        Args:
            public_key: The certificate's public key.

        Returns:
            tuple: (status, issues). issues names the curve when the curve
            itself is not acceptable, e.g. "Usage of curve sect233k1 is
            Deprecated".

        Raises:
            ValueError: If the key type or curve is not in the tables.
        """
        curve = None
        if isinstance(public_key, rsa.RSAPublicKey):
            algorithm, key_size = "RSA", public_key.key_size
        elif isinstance(public_key, dsa.DSAPublicKey):
            algorithm, key_size = "DSA", public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            algorithm, key_size, curve = "ECDSA", public_key.key_size, public_key.curve.name
        else:
            for key_class, (algorithm, curve, key_size) in EDDSA_KEYS.items():
                if isinstance(public_key, key_class):
                    break
            else:
                raise ValueError(f"Unsupported key: {type(public_key).__name__}")

        status = None
        for condition, rule_status in _key_length_rules().get(algorithm.upper(), []):
            if _matches(key_size, condition):
                status = rule_status
                break
        if status is None:
            raise ValueError(f"Unsupported key: {algorithm} {key_size} bits")

        issues = []
        if curve is not None:
            curve_status = CSVParser.get_curve_status(curve)
            if curve_status != ACCEPTABLE:
                issues.append(f"Usage of curve {curve} is {curve_status}")
            status = _worst(status, curve_status)
        return status, issues
