"""
Parsing and checking the domain given to the API.
"""

import re
import socket

from src.fetch.network import MAX_ADDRESSES, FetchError, _public_addresses

DEFAULT_PORT = 443
# Optional scheme, host name (labels of letters, digits, "-" and "_"; the
# top-level domain is letters or an internationalised "xn--" label) and
# optional port
DOMAIN_PATTERN = re.compile(
    r"^(?:https?://)?"
    r"((?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59}))"
    r"(?::\d{1,5})?$",
    re.IGNORECASE,
)
MAX_HOSTNAME_LENGTH = 253


def is_valid_domain(domain: str) -> bool:
    """Check that the domain is well formed (optional scheme and port)."""
    match = DOMAIN_PATTERN.match(domain)
    return match is not None and len(match.group(1)) <= MAX_HOSTNAME_LENGTH


def split_host_port(domain: str) -> tuple[str, int | None]:
    """
    'https://example.com:8443' -> ('example.com', 8443)
    'example.com' -> ('example.com', 443)
    The port is None if it is not a number between 1 and 65535.
    """
    host = re.sub(r"^https?://", "", domain)
    if ":" not in host:
        return host, DEFAULT_PORT
    host, port = host.rsplit(":", 1)
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        return host, None
    return host, int(port)


def is_reachable(domain: str, port: int = DEFAULT_PORT) -> bool:
    """
    Check that a TCP connection to the domain (host part only) can be opened.
    Only public addresses are tried: the host is resolved and checked once
    and the connection made to a checked address (see src/fetch/network.py).
    """
    host, _ = split_host_port(domain)
    try:
        addresses = _public_addresses(host, port)
    except FetchError:
        return False
    for address in addresses[:MAX_ADDRESSES]:
        try:
            with socket.create_connection((address, port), timeout=30):
                return True
        except OSError:
            continue
    return False
