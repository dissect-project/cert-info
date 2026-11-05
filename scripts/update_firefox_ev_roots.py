"""
Extract Firefox's list of EV-enabled roots into src/trust/data/firefox-ev-roots.csv.

Firefox first tries to build an Extended Validation (EV) chain for each EV
policy OID in the leaf certificate. In that attempt, a root only counts as
trusted if Firefox's list (security/certverifier/ExtendedValidation.cpp)
registers it for that policy. The path builder uses the same list so that
EV chains, which can go through cross-signed roots, match Firefox's.

Usage:
    python scripts/update_firefox_ev_roots.py [output.csv]
"""

import csv
import os
import re
import sys

import requests

SOURCE_URL = ("https://raw.githubusercontent.com/mozilla-firefox/firefox/refs/heads/release/"
              "security/certverifier/ExtendedValidation.cpp")
DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "trust", "data", "firefox-ev-roots.csv"
)
# One entry: // subject comment, "policy OID", "OID name", { fingerprint bytes }
ENTRY = re.compile(
    r"//\s*(?P<subject>[^\n]*)\n\s*\"(?P<oid>\d+(?:\.\d+)+)\",\s*\"(?P<name>[^\"]*)\",\s*"
    r"\{(?P<fingerprint>[^}]*)\}"
)


def parse(source: str) -> list:
    """(policy OID, SHA-256 fingerprint, OID name, subject) for each EV root."""
    table = source[source.index("kEVInfos[] = {"):]
    table = table[:table.index("\n};")]
    # The DEBUG entries are test roots that are not in the trust store
    table = re.sub(r"#ifdef DEBUG.*?#endif", "", table, flags=re.S)
    entries = []
    for match in ENTRY.finditer(table):
        fingerprint = "".join(byte[2:] for byte in re.findall(r"0x[0-9A-Fa-f]{2}", match["fingerprint"]))
        if len(fingerprint) != 64:
            raise SystemExit(f"Unexpected fingerprint for {match['subject']}")
        entries.append((match["oid"], fingerprint.lower(), match["name"], match["subject"].strip()))
    if not entries:
        raise SystemExit("No EV entries found; the source format may have changed")
    return entries


def main(output: str) -> None:
    response = requests.get(SOURCE_URL, timeout=60)
    response.raise_for_status()
    entries = parse(response.text)
    with open(output, "w", newline="", encoding="utf-8") as out:
        writer = csv.writer(out)
        writer.writerow(["policy_oid", "sha256_fingerprint", "policy_name", "root_subject"])
        writer.writerows(sorted(entries))
    print(f"Wrote {len(entries)} EV root entries to {output}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUTPUT)
