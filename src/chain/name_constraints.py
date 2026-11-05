"""
Name constraints, as Firefox (mozilla::pkix) applies them during path
building.

A CA certificate's Name Constraints extension lists the names the
certificates below it may (permitted subtrees) or may not (excluded subtrees)
contain. NSS also imposes constraints on two roots that lack the extension.
The constraints of every CA in a path apply to every certificate below it.
Unlike RFC 5280, mozilla::pkix makes no exception for self-issued CA
certificates.

Checked name types:
    dNSName      the SAN DNS names (for a leaf without SAN DNS names or IP
                 addresses, a Common Name that looks like a host name)
    iPAddress    the SAN IP addresses
    directoryName  the certificate's subject

A name type is only restricted by permitted subtrees if the constraints have
at least one permitted subtree of that type. A name inside any excluded
subtree is never allowed.
"""

import ipaddress
import re

from cryptography import x509

from src.chain.certificate_rules import extension

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

_HOSTNAME = re.compile(r"^(\*\.)?([a-z0-9_]([a-z0-9_-]*[a-z0-9_])?\.)*[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?\.?$", re.I)


def constraints_of(ca: x509.Certificate) -> x509.NameConstraints | None:
    """The CA's name constraints: its extension, or the ones NSS imposes."""
    return extension(ca, x509.NameConstraints) or IMPOSED_NAME_CONSTRAINTS.get(ca.subject.public_bytes())


def _names(cert: x509.Certificate, is_leaf: bool) -> tuple[list, list]:
    """(DNS names, IP addresses) of a certificate."""
    san = extension(cert, x509.SubjectAlternativeName)
    dns = san.get_values_for_type(x509.DNSName) if san is not None else []
    ips = san.get_values_for_type(x509.IPAddress) if san is not None else []
    if is_leaf and not dns and not ips:
        # mozilla::pkix treats the CN of such a leaf as a DNS name or IP address
        for attribute in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
            value = attribute.value
            try:
                ips.append(ipaddress.ip_address(value))
            except ValueError:
                if _HOSTNAME.match(value):
                    dns.append(value)
    return dns, ips


def _dns_in_subtree(name: str, base: str) -> bool:
    """
    Whether a DNS name is inside a dNSName subtree: "example.com" covers
    example.com and its subdomains; ".example.com" covers only subdomains;
    an empty base covers everything.
    """
    name, base = name.lower().rstrip("."), base.lower().rstrip(".")
    if not base:
        return True
    if base.startswith("."):
        return name.endswith(base)
    return name == base or name.endswith("." + base)


def _wildcard_overlaps(name: str, base: str) -> bool:
    """Whether some host a wildcard name (*.domain) covers is inside the subtree."""
    domain = name[2:].lower().rstrip(".")
    stripped = base.lower().rstrip(".").lstrip(".")
    # The subtree contains the wildcard's whole domain ...
    if _dns_in_subtree("x." + domain, base):
        return True
    # ... or is one of the hosts the wildcard covers (one label below)
    return stripped.endswith("." + domain) and stripped.count(".") == domain.count(".") + 1


def _directory_in_subtree(subject: x509.Name, base: x509.Name) -> bool:
    """Whether a subject is inside a directoryName subtree (starts with its RDNs)."""
    return list(subject.rdns[:len(base.rdns)]) == list(base.rdns)


def _ip_in_subtree(ip, network) -> bool:
    return ip.version == network.version and ip in network


def violates(constraints: x509.NameConstraints, cert: x509.Certificate, is_leaf: bool) -> bool:
    """Whether a certificate below a constrained CA breaks its constraints."""
    permitted = constraints.permitted_subtrees or []
    excluded = constraints.excluded_subtrees or []
    dns, ips = _names(cert, is_leaf)
    subjects = [cert.subject] if cert.subject.rdns else []

    def check(names, general_type, inside, overlaps=None):
        allowed = [g.value for g in permitted if isinstance(g, general_type)]
        denied = [g.value for g in excluded if isinstance(g, general_type)]
        for name in names:
            if allowed and not any(inside(name, base) for base in allowed):
                return True
            touches = overlaps if overlaps and isinstance(name, str) and name.startswith("*.") else inside
            if any(touches(name, base) for base in denied):
                return True
        return False

    def dns_inside(name, base):
        # A wildcard is inside a permitted subtree only if all hosts it covers are
        return _dns_in_subtree("x." + name[2:] if name.startswith("*.") else name, base)

    return (check(dns, x509.DNSName, dns_inside, _wildcard_overlaps)
            or check(ips, x509.IPAddress, _ip_in_subtree)
            or check(subjects, x509.DirectoryName, _directory_in_subtree))


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
