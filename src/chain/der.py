"""
A minimal DER reader, for the few places where Firefox looks at the encoded
form of a certificate rather than its decoded values (signature algorithm
identifiers, the encoding of name attributes) and for OCSP and SCT
structures.
"""

from dataclasses import dataclass


class DERError(ValueError):
    """The data is not valid DER."""


@dataclass(frozen=True)
class Element:
    tag: int
    content: bytes
    encoded: bytes      # tag, length and content


def read(data: bytes, position: int = 0) -> tuple[Element, int]:
    """The DER element at `position`, and the position after it."""
    if position + 2 > len(data):
        raise DERError("truncated")
    tag, length = data[position], data[position + 1]
    start = position + 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or start + count > len(data):
            raise DERError("unsupported length")
        length = int.from_bytes(data[start:start + count], "big")
        start += count
    end = start + length
    if end > len(data):
        raise DERError("truncated")
    return Element(tag, data[start:end], data[position:end]), end


def parse(data: bytes) -> Element:
    """The single DER element that `data` consists of."""
    element, end = read(data)
    if end != len(data):
        raise DERError("trailing data")
    return element


def children(content: bytes) -> list:
    """The elements of a constructed element's content (e.g. a SEQUENCE)."""
    elements, position = [], 0
    while position < len(content):
        element, position = read(content, position)
        elements.append(element)
    return elements


def decode_oid(content: bytes) -> str:
    """Dotted form of an OBJECT IDENTIFIER's content."""
    if not content:
        raise DERError("empty OID")
    values, value = [], 0
    for byte in content:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            values.append(value)
            value = 0
    first = min(values[0] // 40, 2)
    return ".".join(str(v) for v in [first, values[0] - 40 * first, *values[1:]])
