"""
Downloading a missing issuer through the certificate's Authority Information
Access (AIA) caIssuers URLs. Firefox never does this; the path builder only
uses it when no trusted chain exists.
"""

import warnings
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.utils import CryptographyDeprecationWarning

from src.chain.signatures import is_signed_by
from src.fetch.network import FetchError, fetch
from src.trust.store import load_pem_certificates


def fetch_issuer_from_aia(cert: x509.Certificate) -> Optional[x509.Certificate]:
    """
    Download the issuer of a certificate from its AIA caIssuers URLs. Only a
    certificate that actually signed the child is returned.

    Args:
        cert (x509.Certificate): The certificate whose issuer is missing.

    Returns:
        x509.Certificate: The issuer, or None if it could not be fetched.
    """
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except Exception:
        return None
    urls = [desc.access_location.value for desc in aia
            if desc.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS]
    for url in urls:
        try:
            content = fetch(url)
        except FetchError:
            continue
        for candidate in _parse_aia_response(content):
            if is_signed_by(cert, candidate):
                return candidate
    return None


def _parse_aia_response(content: bytes) -> list:
    """Parse an AIA response, which can be DER, PEM or PKCS#7 (DER or PEM)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        try:
            return [x509.load_der_x509_certificate(content)]
        except ValueError:
            pass
        certs = load_pem_certificates(content)
        if certs:
            return certs
        for loader in (pkcs7.load_der_pkcs7_certificates, pkcs7.load_pem_pkcs7_certificates):
            try:
                return list(loader(content))
            except ValueError:
                continue
    return []
