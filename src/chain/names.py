"""
Names as mozilla::pkix (pkixnames.cpp) validates and compares them: DNS
names, email addresses (RFC 822 names) and IPv4 addresses written in a
Common Name. Used for hostname matching (src/validation/certificate_validator.py)
and name constraints (src/chain/name_constraints.py).
"""

PRESENTED = "presented"         # a name in a certificate
REFERENCE = "reference"         # the hostname being checked
CONSTRAINT = "constraint"       # a name constraint

MAX_DNS_ID_LENGTH = 253
MAX_LABEL_LENGTH = 63
_RFC822_LOCAL_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-/=?^_`{|}~")


class InvalidName(ValueError):
    """A name that mozilla::pkix refuses to compare (ERROR_BAD_DER)."""


def is_valid_dns_id(name: str, role: str, allow_wildcards: bool = False) -> bool:
    """IsValidDNSID: letters, digits, '_' and '-' in labels of 1 to 63 characters."""
    if len(name) > MAX_DNS_ID_LENGTH:
        return False
    if role == CONSTRAINT and name == "":
        return True
    position, dot_count = 0, 0
    label_length, all_numeric, ends_with_hyphen = 0, False, False
    is_wildcard = allow_wildcards and name.startswith("*")
    is_first = not is_wildcard
    if is_wildcard:
        if name[1:2] != ".":
            return False
        position, dot_count = 2, 1
    if position >= len(name):
        return False
    for char in name[position:]:
        if char == "-":
            if label_length == 0 and role != REFERENCE:
                return False
            all_numeric, ends_with_hyphen = False, True
            label_length += 1
        elif char.isascii() and char.isdigit():
            if label_length == 0:
                all_numeric = True
            ends_with_hyphen = False
            label_length += 1
        elif (char.isascii() and char.isalpha()) or char == "_":
            all_numeric, ends_with_hyphen = False, False
            label_length += 1
        elif char == ".":
            dot_count += 1
            if label_length == 0 and (role != CONSTRAINT or not is_first):
                return False
            if ends_with_hyphen and role != REFERENCE:
                return False
            label_length = 0
        else:
            return False
        if label_length > MAX_LABEL_LENGTH:
            return False
        is_first = False
    if label_length == 0 and role != REFERENCE:
        return False
    if ends_with_hyphen and role != REFERENCE:
        return False
    if all_numeric:
        return False
    if is_wildcard:
        label_count = dot_count if label_length == 0 else dot_count + 1
        if label_count < 3:     # like NSS: two labels after the wildcard
            return False
    return True


def _ascii_lower(text: str) -> str:
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in text)


def _equal_ignoring_ascii_case(a: str, b: str) -> bool:
    return _ascii_lower(a) == _ascii_lower(b)


def match_dns_id(presented: str, reference: str, role: str = REFERENCE, permitted: bool = True,
                 allow_dotless_subdomains: bool = True) -> bool:
    """
    MatchPresentedDNSIDWithReferenceDNSID: whether a DNS name of a certificate
    matches a hostname (role REFERENCE) or falls within a name constraint
    (role CONSTRAINT, in a permitted or excluded subtree).

    Raises:
        InvalidName: If either name is not a valid DNS name for its role.
    """
    if not is_valid_dns_id(presented, PRESENTED, allow_wildcards=True):
        raise InvalidName(presented)
    if not is_valid_dns_id(reference, role):
        raise InvalidName(reference)

    if role == CONSTRAINT and len(presented) > len(reference):
        if reference == "":
            return True
        if reference.startswith("."):
            presented = presented[len(presented) - len(reference):]
        elif allow_dotless_subdomains:
            dot = len(presented) - len(reference) - 1
            if presented[dot] != ".":
                return False
            presented = presented[dot + 1:]

    if presented.startswith("*"):
        presented = presented[1:]
        # A wildcard covers one label: skip the reference's first label,
        # except for permitted subtrees (*.example.com is only within
        # example.com or .example.com)
        if role != CONSTRAINT or not permitted:
            dot = reference.find(".")
            if dot < 0:
                return False
            reference = reference[dot:]

    if not presented or len(reference) < len(presented):
        return False
    if not _equal_ignoring_ascii_case(presented, reference[:len(presented)]):
        return False
    if presented.endswith("."):
        raise InvalidName(presented)
    rest = reference[len(presented):]
    if role != CONSTRAINT and rest == ".":
        return True     # an absolute hostname ("example.com.")
    return rest == ""


def is_valid_rfc822_name(name: str) -> bool:
    """IsValidRFC822Name: local@domain, a dot-atom local part and a valid DNS domain."""
    local, at, domain = name.partition("@")
    if not at or not local:
        return False
    start_of_atom = True
    for char in local:
        if char == ".":
            if start_of_atom:
                return False
            start_of_atom = True
        elif char in _RFC822_LOCAL_CHARS:
            start_of_atom = False
        else:
            return False
    return not start_of_atom and is_valid_dns_id(domain, PRESENTED)


def match_rfc822_constraint(presented: str, constraint: str, permitted: bool) -> bool:
    """
    Whether an email address falls within an rfc822Name constraint: a whole
    address ("user@example.com"), a host ("example.com", that host only) or
    a domain (".example.com", its subdomains).

    Raises:
        InvalidName: If the address or the constraint is invalid.
    """
    if not is_valid_rfc822_name(presented):
        raise InvalidName(presented)
    if "@" not in constraint:
        host = presented.partition("@")[2]
        return match_dns_id(host, constraint, CONSTRAINT, permitted, allow_dotless_subdomains=False)
    if not is_valid_rfc822_name(constraint):
        raise InvalidName(constraint)
    return _equal_ignoring_ascii_case(presented, constraint)


def parse_ipv4(text: str) -> bytes | None:
    """The address of a dotted-decimal IPv4 string (as in a Common Name), or None."""
    parts = text.split(".")
    if len(parts) != 4:
        return None
    octets = []
    for part in parts:
        if not part or len(part) > 3 or not (part.isascii() and part.isdigit()) \
                or (len(part) > 1 and part[0] == "0") or int(part) > 255:
            return None
        octets.append(int(part))
    return bytes(octets)
