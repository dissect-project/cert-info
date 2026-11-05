"""
Download OneCRL, Mozilla's list of revoked or distrusted CA certificates, into
src/trust/data/mozilla-onecrl.json.

Firefox gets OneCRL from the "security-state/onecrl" Remote Settings
collection and treats every listed certificate as revoked during path
building (it then tries other paths). Each record identifies a certificate
either by issuer name and serial number, or by subject name and SHA-256 hash
of its public key (SubjectPublicKeyInfo). Firefox applies every record; the
records' "enabled" field is not used.

Usage:
    python scripts/update_mozilla_onecrl.py [output.json]
"""

import json
import os
import sys
from datetime import datetime, timezone

import requests

CHANGESET_URL = ("https://firefox.settings.services.mozilla.com/v1/buckets/security-state/"
                 "collections/onecrl/changeset?_expected=0")
DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "trust", "data", "mozilla-onecrl.json"
)


def main(output: str) -> None:
    changeset = requests.get(CHANGESET_URL, timeout=120).json()
    issuer_serial, subject_key = set(), set()
    for record in changeset["changes"]:
        if record.get("deleted"):
            continue
        if record.get("issuerName") and record.get("serialNumber"):
            issuer_serial.add((record["issuerName"], record["serialNumber"]))
        elif record.get("subject") and record.get("pubKeyHash"):
            subject_key.add((record["subject"], record["pubKeyHash"]))
    if not issuer_serial and not subject_key:
        raise SystemExit("No OneCRL records found")
    published = datetime.fromtimestamp(changeset["timestamp"] / 1000, timezone.utc)
    data = {
        "source": CHANGESET_URL,
        "collection_timestamp": published.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "description": "base64 DER issuer name + base64 serial number bytes; "
                       "base64 DER subject name + base64 SHA-256 of SubjectPublicKeyInfo",
        "issuer_serial": sorted(issuer_serial),
        "subject_pubkey_hash": sorted(subject_key),
    }
    with open(output, "w", encoding="utf-8") as out:
        json.dump(data, out, indent=0)
    print(f"Wrote {len(issuer_serial) + len(subject_key)} OneCRL entries to {output}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUTPUT)
