"""
Signature verification for certificates, CRLs and OCSP responses.

Certificate.verify_directly_issued_by is not used because it refuses SHA-1
signatures, which are still found in roots and old chains.
"""

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa


class UnsupportedSignature(Exception):
    """The signature algorithm or the issuer's key type is not supported."""


def verify_signed_data(public_key, signature: bytes, data: bytes,
                       hash_algorithm, parameters=None) -> None:
    """
    Verify a signature made with any key type cryptography supports, with any
    hash (including SHA-1).

    Args:
        public_key: The signer's public key.
        signature (bytes): The signature.
        data (bytes): The signed data.
        hash_algorithm: The hash (None for EdDSA).
        parameters: For RSA, PKCS1v15() or PSS(...) (default PKCS1v15); for
            ECDSA, ECDSA(hash) (default built from hash_algorithm).

    Raises:
        InvalidSignature: If the signature is wrong.
        UnsupportedSignature: If the algorithm or key type is not supported.
    """
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data, parameters or padding.PKCS1v15(), hash_algorithm)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, parameters or ec.ECDSA(hash_algorithm))
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(signature, data)
        elif isinstance(public_key, dsa.DSAPublicKey):
            public_key.verify(signature, data, hash_algorithm)
        else:
            raise UnsupportedSignature(f"Unsupported key type: {type(public_key).__name__}")
    except (InvalidSignature, UnsupportedSignature):
        raise
    except (ValueError, TypeError, UnsupportedAlgorithm) as e:
        # Unsupported algorithm, or a key type that cannot match the signature
        raise UnsupportedSignature(str(e)) from e


def verify_signature(child: x509.Certificate, issuer: x509.Certificate) -> None:
    """
    Verify that the issuer's key produced the child's signature.

    Certificate.verify_directly_issued_by is not used because it refuses
    SHA-1 signatures, which are still found in roots and old chains.

    Raises:
        InvalidSignature: If the names do not match or the signature is wrong.
        UnsupportedSignature: If the algorithm or key type is not supported.
    """
    if child.issuer != issuer.subject:
        raise InvalidSignature("Issuer name does not match")
    try:
        public_key = issuer.public_key()
        hash_algorithm = child.signature_hash_algorithm
        parameters = child.signature_algorithm_parameters
    except (ValueError, UnsupportedAlgorithm) as e:
        raise UnsupportedSignature(str(e)) from e
    verify_signed_data(public_key, child.signature, child.tbs_certificate_bytes,
                       hash_algorithm, parameters)


def is_signed_by(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    """
    Check that the issuer's name matches the child's issuer name and that the
    issuer's key verifies the child's signature.
    """
    try:
        verify_signature(child, issuer)
        return True
    except (InvalidSignature, UnsupportedSignature):
        return False


def is_self_signed(cert: x509.Certificate) -> bool:
    """
    Check that the subject equals the issuer and the certificate's signature
    verifies with its own key.
    """
    return is_signed_by(cert, cert)
