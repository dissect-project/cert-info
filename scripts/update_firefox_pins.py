"""
Extract Firefox's static public key pins into src/trust/data/firefox-pins.json.

Firefox ships a short list of hosts (Mozilla and Google services, among
others) whose chains must contain one of a set of keys (pins). A chain to a
Mozilla root that contains none of them is rejected, and Firefox tries other
paths. The list is compiled into Firefox
(security/manager/ssl/StaticHPKPins.h) with an expiration time, after which
Firefox stops enforcing it.

Usage:
    python scripts/update_firefox_pins.py [output.json]
"""

import json
import os
import re
import sys
from datetime import datetime, timezone

import requests

SOURCE_URL = ("https://raw.githubusercontent.com/mozilla-firefox/firefox/refs/heads/release/"
              "security/manager/ssl/StaticHPKPins.h")
DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "trust", "data", "firefox-pins.json"
)
FINGERPRINT = re.compile(r'static const char (k\w+Fingerprint)\[\]\s*=\s*"([^"]+)";')
PINSET = re.compile(r"static const char\* const kPinset_(\w+)_Data\[\]\s*=\s*\{(.*?)\};", re.S)
# { "host", includeSubdomains, testMode, isMoz, id, &kPinset_name },
ENTRY = re.compile(r'\{\s*"([^"]+)",\s*(true|false),\s*(true|false),\s*(?:true|false),\s*-?\d+,\s*'
                   r'(?:&kPinset_(\w+)|nullptr)\s*\}')
EXPIRATION = re.compile(r"kPreloadPKPinsExpirationTime\s*=\s*INT64_C\((\d+)\)")


def parse(source: str) -> dict:
    """The pinsets, pinned hosts and expiration time of StaticHPKPins.h."""
    fingerprints = dict(FINGERPRINT.findall(source))
    pinsets = {
        name: [fingerprints[ref] for ref in re.findall(r"k\w+Fingerprint", body)]
        for name, body in PINSET.findall(source)
    }
    entries = [
        {"host": host, "include_subdomains": subdomains == "true", "test_mode": test == "true",
         "pinset": pinset or None}
        for host, subdomains, test, pinset in ENTRY.findall(source)
    ]
    expiration = EXPIRATION.search(source)
    if not entries or not pinsets or not expiration:
        raise SystemExit("No pins found; the source format may have changed")
    expires = datetime.fromtimestamp(int(expiration.group(1)) / 1_000_000, timezone.utc)
    return {
        "source": SOURCE_URL,
        "expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "description": "pinsets: base64 SHA-256 hashes of SubjectPublicKeyInfo",
        "pinsets": pinsets,
        "entries": entries,
    }


def main(output: str) -> None:
    response = requests.get(SOURCE_URL, timeout=60)
    response.raise_for_status()
    data = parse(response.text)
    with open(output, "w", encoding="utf-8") as out:
        json.dump(data, out, indent=1)
    print(f"Wrote {len(data['entries'])} pinned hosts to {output}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUTPUT)
