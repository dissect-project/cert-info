"""
Retrieving what a server sends in the TLS handshake, with openssl s_client:
its certificates, its stapled OCSP response and the Signed Certificate
Timestamps (SCTs) it sends in the TLS extension.

Like Firefox, the client asks for OCSP stapling (status_request) and SCTs
(signed_certificate_timestamp). The stapled response and SCTs are read from
the raw handshake messages printed by -msg: in TLS 1.3 they are extensions of
the leaf's entry in the Certificate message; in TLS 1.2 the SCTs are a
ServerHello extension and the OCSP response has its own CertificateStatus
message.
"""

import os
import re
import subprocess
from dataclasses import dataclass, field

PEM_PATTERN = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)

# ClientHello settings taken from Firefox (TLS 1.3 and TLS 1.2 cipher suites,
# signature algorithms and groups). Servers choose their certificate from these.
FIREFOX_TLS_ARGS = [
    "-ciphersuites", "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
    "-cipher", "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
               "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
               "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
               "ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:"
               "ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA",
    "-sigalgs", "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:"
                "rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:"
                "rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512",
    "-groups", "X25519:P-256:P-384:P-521",
    "-alpn", "h2,http/1.1",
]
# Settings for servers that only support old protocols or ciphers
LEGACY_TLS_ARGS = ["-cipher", "ALL:@SECLEVEL=0", "-legacy_server_connect"]
# Handshakes tried in order until one returns certificates
OPENSSL_ATTEMPTS = (FIREFOX_TLS_ARGS, [], LEGACY_TLS_ARGS)
# Ask for a stapled OCSP response and for SCTs, and print the handshake
# messages. -ct needs a CT log list; an empty one is given because the SCTs
# are verified by cert-info (src/validation/transparency.py), not by openssl.
EMPTY_CT_LOG_LIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "empty-ct-logs.cnf")
HANDSHAKE_ARGS = ["-status", "-ct", "-ctlogfile", EMPTY_CT_LOG_LIST, "-msg"]

# TLS handshake message and extension types
_CERTIFICATE = 11
_CERTIFICATE_STATUS = 22
_SERVER_HELLO = 2
_EXT_STATUS_REQUEST = 5
_EXT_SCT = 18
_OCSP_STATUS_TYPE = 1
_RECEIVED_MESSAGE = re.compile(r"^<<< [^,]+, Handshake \[length [0-9a-fA-F]+\]")
_HEX_LINE = re.compile(r"^\s+((?:[0-9a-f]{2} ?)+)\s*$")


@dataclass
class Handshake:
    """What the server sent: certificates (PEM, leaf first), a stapled OCSP
    response (DER) and the SCT list of the TLS extension (encoded
    SignedCertificateTimestampList), if any."""
    certificates: list = field(default_factory=list)
    stapled_ocsp: bytes | None = None
    tls_scts: bytes | None = None


class _Reader:
    """Reads TLS presentation-language fields from bytes."""

    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, length: int) -> bytes:
        if self.pos + length > len(self.data):
            raise ValueError("truncated")
        chunk = self.data[self.pos:self.pos + length]
        self.pos += length
        return chunk

    def number(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")

    def vector(self, length_size: int) -> bytes:
        return self.take(self.number(length_size))

    def at_end(self) -> bool:
        return self.pos >= len(self.data)


def _extensions(data: bytes) -> dict:
    """Extension type -> data, from an encoded extension list (without its length)."""
    reader, extensions = _Reader(data), {}
    while not reader.at_end():
        ext_type = reader.number(2)
        extensions[ext_type] = reader.vector(2)
    return extensions


def _ocsp_from_status(data: bytes) -> bytes | None:
    """The OCSP response of a CertificateStatus structure."""
    reader = _Reader(data)
    if reader.number(1) != _OCSP_STATUS_TYPE:
        return None
    return reader.vector(3)


def received_messages(output: str) -> list:
    """(type, body) of each handshake message received, from openssl -msg output."""
    messages, current = [], None
    for line in output.splitlines():
        if _RECEIVED_MESSAGE.match(line):
            current = bytearray()
            messages.append(current)
            continue
        hex_line = _HEX_LINE.match(line) if current is not None else None
        if hex_line:
            current.extend(bytes.fromhex(hex_line.group(1).replace(" ", "")))
        else:
            current = None
    return [(bytes(m)[0], bytes(m)[4:]) for m in messages if len(m) >= 4]


def parse_handshake(output: str) -> tuple[bytes | None, bytes | None]:
    """(stapled OCSP response, TLS SCT list) from openssl -msg output."""
    ocsp, scts = None, None
    tls13 = "<<< TLS 1.3, Handshake" in output
    for msg_type, body in received_messages(output):
        try:
            reader = _Reader(body)
            if msg_type == _SERVER_HELLO and not tls13:
                reader.take(2 + 32)          # version, random
                reader.vector(1)             # session id
                reader.take(3)               # cipher suite, compression
                if not reader.at_end():
                    scts = _extensions(reader.vector(2)).get(_EXT_SCT, scts)
            elif msg_type == _CERTIFICATE_STATUS:
                ocsp = _ocsp_from_status(body)
            elif msg_type == _CERTIFICATE and tls13:
                reader.vector(1)             # certificate request context
                entries = _Reader(reader.vector(3))
                entries.vector(3)            # the leaf certificate
                leaf_extensions = _extensions(entries.vector(2))
                if _EXT_STATUS_REQUEST in leaf_extensions:
                    ocsp = _ocsp_from_status(leaf_extensions[_EXT_STATUS_REQUEST])
                scts = leaf_extensions.get(_EXT_SCT, scts)
        except ValueError:
            continue
    return ocsp or None, scts or None


def chain_certificates(output: str) -> list:
    """
    The PEM certificates of the "Certificate chain" section of openssl
    s_client output. Certificates printed elsewhere, such as the OCSP
    responder's certificate in the stapled response, are not part of it.
    """
    start = output.find("\nCertificate chain\n")
    if start < 0:
        return []
    end = output.find("\n---\n", start + 1)
    return PEM_PATTERN.findall(output[start:end if end >= 0 else len(output)])


def fetch_handshake(domain: str, port: int = 443) -> Handshake:
    """
    Connect to the server with openssl s_client and return what it sent.

    The first attempt offers the same signature algorithms, groups and
    cipher suites as Firefox, so a server with several certificates (e.g.
    RSA and ECDSA) sends the one Firefox receives. If that handshake fails,
    OpenSSL's defaults are tried, then legacy settings for old servers.
    """
    for extra_args in OPENSSL_ATTEMPTS:
        cmd = ["openssl", "s_client", "-connect", f"{domain}:{port}",
               "-servername", domain, "-showcerts", *HANDSHAKE_ARGS, *extra_args]
        try:
            # errors="replace": openssl prints certificate names in their
            # raw encoding (not always UTF-8); the PEM blocks are ASCII.
            result = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True,
                                    text=True, encoding="utf-8", errors="replace",
                                    timeout=20, check=False)
        except (subprocess.TimeoutExpired, OSError):
            continue
        certs = chain_certificates(result.stdout)
        if certs:
            ocsp, scts = parse_handshake(result.stdout)
            return Handshake(certs, ocsp, scts)
    return Handshake()


def fetch_server_certificates(domain: str, port: int = 443) -> list:
    """The PEM certificates sent by the server, in the order it sent them."""
    return fetch_handshake(domain, port).certificates
