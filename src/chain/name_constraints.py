"""
Name constraints, as Firefox (mozilla::pkix, pkixnames.cpp) applies them
during path building.

A CA certificate's Name Constraints extension lists the names the
certificates below it may (permitted subtrees) or may not (excluded subtrees)
contain. NSS also imposes constraints on two roots that lack the extension.
The constraints of every CA in a path apply to every certificate below it.
Unlike RFC 5280, mozilla::pkix makes no exception for self-issued CA
certificates.

The names of a certificate that are checked:
    every Subject Alternative Name entry;
    the subject, as a directoryName (always, even when empty);
    without a Subject Alternative Name extension, the subject's emailAddress
        attributes, as rfc822Names;
    for a server certificate without SAN DNS names or IP addresses, the
        most specific (last) Common Name, as a DNS name or an IPv4 address.

Each name is compared with the subtrees of its own type:
    dNSName        "example.com" covers it and its subdomains, ".example.com"
                   only subdomains, "" everything. A wildcard name is within
                   a permitted subtree only if all names it covers are.
    iPAddress      address and mask.
    directoryName  permitted: the subject starts with the constraint's RDNs,
                   compared on their encoding. Excluded directoryName
                   subtrees are not supported by mozilla::pkix: any of them
                   rejects every certificate below.
    rfc822Name     a whole address, a host ("example.com", that host only)
                   or a domain (".example.com").
    other types    (URI, otherName, registeredID) not supported: a
                   certificate with such a name is rejected if the
                   constraints have a subtree of the same type.
A name type is only restricted by permitted subtrees if there is at least
one permitted subtree of that type; a name inside an excluded subtree is
never allowed. Invalid names make the certificate unusable.
"""

import ipaddress

from cryptography import x509

from src.chain import der
from src.chain.certificate_rules import extension
from src.chain.names import CONSTRAINT, PRESENTED, InvalidName, is_valid_dns_id, match_dns_id, \
    match_rfc822_constraint, parse_ipv4

# Name constraints NSS imposes on roots without the extension
# (security/nss/lib/certdb/genname.c, builtInNameConstraints)
_ANSSI_SUBJECT = (
    b"\x30\x81\x85"
    b"\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02FR"
    b"\x31\x0F\x30\x0D\x06\x03\x55\x04\x08\x13\x06France"
    b"\x31\x0E\x30\x0C\x06\x03\x55\x04\x07\x13\x05Paris"
    b"\x31\x10\x30\x0E\x06\x03\x55\x04\x0A\x13\x07PM/SGDN"
    b"\x31\x0E\x30\x0C\x06\x03\x55\x04\x0B\x13\x05DCSSI"
    b"\x31\x0E\x30\x0C\x06\x03\x55\x04\x03\x13\x05IGC/A"
    b"\x31\x23\x30\x21\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x01\x16\x14igca@sgdn.pm.gouv.fr"
)
_TUBITAK1_SUBJECT = (
    b"\x30\x81\xd2"
    b"\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02TR"
    b"\x31\x18\x30\x16\x06\x03\x55\x04\x07\x13\x0fGebze - Kocaeli"
    b"\x31\x42\x30\x40\x06\x03\x55\x04\x0a\x13\x39Turkiye Bilimsel ve Teknolojik Arastirma Kurumu - TUBITAK"
    b"\x31\x2d\x30\x2b\x06\x03\x55\x04\x0b\x13\x24Kamu Sertifikasyon Merkezi - Kamu SM"
    b"\x31\x36\x30\x34\x06\x03\x55\x04\x03\x13\x2dTUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1"
)
IMPOSED_NAME_CONSTRAINTS = {
    _ANSSI_SUBJECT: x509.NameConstraints(
        permitted_subtrees=[x509.DNSName(d) for d in (".fr", ".gp", ".gf", ".mq", ".re", ".yt", ".pm",
                                                      ".bl", ".mf", ".wf", ".pf", ".nc", ".tf")],
        excluded_subtrees=None),
    _TUBITAK1_SUBJECT: x509.NameConstraints(
        permitted_subtrees=[x509.DNSName(".tr")], excluded_subtrees=None),
}

_COMMON_NAME = "2.5.4.3"
_EMAIL_ADDRESS = "1.2.840.113549.1.9.1"
_PRINTABLE_STRING, _UTF8_STRING, _TELETEX_STRING, _IA5_STRING = 0x13, 0x0C, 0x14, 0x16


class _Violation(Exception):
    """A name outside the constraints, or one that cannot be checked."""


def constraints_of(ca: x509.Certificate) -> x509.NameConstraints | None:
    """The CA's name constraints: its extension, or the ones NSS imposes."""
    return extension(ca, x509.NameConstraints) or IMPOSED_NAME_CONSTRAINTS.get(ca.subject.public_bytes())


def _attributes(name_der: bytes) -> list:
    """(OID, string tag, value bytes) of every attribute of an encoded Name, in order."""
    attributes = []
    for rdn in der.children(der.parse(name_der).content):
        for ava in der.children(rdn.content):
            oid, value = der.children(ava.content)
            attributes.append((der.decode_oid(oid.content), value.tag, value.content))
    return attributes


def _presented_names(cert: x509.Certificate, is_leaf: bool) -> list:
    """The names of a certificate that name constraints apply to (see above)."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        san = None
    except Exception:
        raise _Violation("unreadable Subject Alternative Name")
    names = list(san) if san is not None else []
    fall_back_to_cn = is_leaf and not any(isinstance(n, (x509.DNSName, x509.IPAddress)) for n in names)
    names.append(x509.DirectoryName(cert.subject))
    attributes = _attributes(cert.subject.public_bytes())
    if san is None:
        for oid, tag, value in attributes:
            if oid == _EMAIL_ADDRESS:
                if tag != _IA5_STRING:
                    raise _Violation("emailAddress is not an IA5String")
                names.append(x509.RFC822Name(value.decode("ascii", "replace")))
    if fall_back_to_cn:
        common_names = [(tag, value) for oid, tag, value in attributes if oid == _COMMON_NAME]
        if common_names:
            tag, value = common_names[-1]
            text = value.decode("latin-1")
            if tag in (_PRINTABLE_STRING, _UTF8_STRING, _TELETEX_STRING):
                if is_valid_dns_id(text, PRESENTED, allow_wildcards=True):
                    names.append(x509.DNSName(text))
                elif parse_ipv4(text) is not None:
                    names.append(x509.IPAddress(ipaddress.ip_address(parse_ipv4(text))))
    return names


def _ip_matches(address, network) -> bool:
    """Whether an address is within an address/mask constraint (same IP version only)."""
    if address.version != network.version:
        return False
    mask = network.netmask.packed
    return all(a & m == n & m for a, n, m in zip(address.packed, network.network_address.packed, mask))


def _directory_matches(subject: x509.Name, constraint: x509.Name, permitted: bool) -> bool:
    """MatchPresentedDirectoryNameWithConstraint: RDN by RDN, on the encoded values."""
    presented_rdns = der.children(der.parse(subject.public_bytes()).content)
    constraint_rdns = der.children(der.parse(constraint.public_bytes()).content)
    if not permitted:
        if constraint_rdns or presented_rdns:
            raise _Violation("excluded directoryName subtrees are not supported")
        return True
    for index, constraint_rdn in enumerate(constraint_rdns):
        if index >= len(presented_rdns):
            return False
        constraint_avas = der.children(constraint_rdn.content)
        presented_avas = der.children(presented_rdns[index].content)
        if len(constraint_avas) != len(presented_avas):
            return False
        for constraint_ava, presented_ava in zip(constraint_avas, presented_avas):
            c_type, c_value = der.children(constraint_ava.content)
            p_type, p_value = der.children(presented_ava.content)
            strings = {_PRINTABLE_STRING, _UTF8_STRING}
            same_tag = c_value.tag == p_value.tag or {c_value.tag, p_value.tag} <= strings
            if c_type.content != p_type.content or c_value.content != p_value.content or not same_tag:
                return False
    return True


def _matches(name, base, permitted: bool) -> bool:
    if isinstance(name, x509.DNSName):
        return match_dns_id(name.value, base.value, CONSTRAINT, permitted)
    if isinstance(name, x509.IPAddress):
        return _ip_matches(name.value, base.value)
    if isinstance(name, x509.DirectoryName):
        return _directory_matches(name.value, base.value, permitted)
    if isinstance(name, x509.RFC822Name):
        return match_rfc822_constraint(name.value, base.value, permitted)
    raise _Violation(f"name constraints on {type(name).__name__} are not supported")


def _check(name, constraints: x509.NameConstraints) -> None:
    """CheckPresentedIDConformsToConstraints: raises _Violation if the name is not allowed."""
    for subtrees, permitted in ((constraints.permitted_subtrees, True), (constraints.excluded_subtrees, False)):
        found_match = found_mismatch = False
        for base in subtrees or []:
            if type(base) is not type(name):
                continue
            if _matches(name, base, permitted):
                if not permitted:
                    raise _Violation("name in an excluded subtree")
                found_match = True
            else:
                found_mismatch = True
        if permitted and found_mismatch and not found_match:
            raise _Violation("name outside the permitted subtrees")


def violates(constraints: x509.NameConstraints, cert: x509.Certificate, is_leaf: bool) -> bool:
    """Whether a certificate below a constrained CA breaks its constraints."""
    try:
        for name in _presented_names(cert, is_leaf):
            _check(name, constraints)
    except (_Violation, InvalidName, der.DERError, ValueError):
        return True
    return False


def path_violations(certs: list) -> list:
    """
    Positions (0 = leaf) of the certificates in a path, leaf first, that break
    the name constraints of a CA above them.
    """
    bad = set()
    for position, ca in enumerate(certs[1:], start=1):
        constraints = constraints_of(ca)
        if constraints is None:
            continue
        for below in range(position):
            if violates(constraints, certs[below], is_leaf=below == 0):
                bad.add(below)
    return sorted(bad)


def permits(ca: x509.Certificate, certs_below: list) -> bool:
    """Whether a CA's constraints allow every certificate below it (leaf first)."""
    constraints = constraints_of(ca)
    if constraints is None:
        return True
    return not any(
        violates(constraints, cert, is_leaf=index == 0)
        for index, cert in enumerate(certs_below)
    )
