"""
Firefox's static public key pinning (PublicKeyPinningService.cpp).

For a few hosts, a chain that ends at a Mozilla root must contain at least
one key of the host's pinset. Firefox checks this when it reaches a trust
anchor and tries other paths if it fails. Pins in test mode are not enforced,
and none are once the list has expired.
"""

import hashlib
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from src.trust.store import StaticPins


def pinset_for(pins: StaticPins, hostname: str | None, now: datetime) -> set | None:
    """
    The SHA-256 SPKI hashes a chain for this host must include, or None if
    the host has no enforced pins.

    The host and then each parent domain (down to two labels) is looked up;
    an entry for a parent domain only applies if it includes subdomains.
    """
    if not hostname or pins.expiration is None or now > pins.expiration:
        return None
    host = hostname.lower().rstrip(".")
    candidate = host
    while "." in candidate:
        entry = pins.entries.get(candidate)
        if entry is not None:
            include_subdomains, test_mode, pinset = entry
            if candidate == host or include_subdomains:
                return None if test_mode else pinset
        candidate = candidate.split(".", 1)[1]
    return None


def spki_sha256(cert: x509.Certificate) -> bytes | None:
    try:
        spki = cert.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
    except Exception:
        return None
    return hashlib.sha256(spki).digest()


def chain_has_valid_pins(pins: StaticPins, hostname: str | None, certs: list, now: datetime) -> bool:
    """Whether a chain (leaf first, ending at a Mozilla root) satisfies the host's pins."""
    pinset = pinset_for(pins, hostname, now)
    return pinset is None or any(spki_sha256(cert) in pinset for cert in certs)
