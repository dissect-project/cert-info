"""
Extract the Certificate Transparency logs Firefox knows into
src/trust/data/firefox-ct-logs.json.

Firefox only accepts a certificate that chains to a Mozilla root if it comes
with enough Signed Certificate Timestamps (SCTs) from these logs (see
src/validation/transparency.py). The list is compiled into Firefox
(security/ct/CTKnownLogs.h) together with an expiration time: once it has
passed, Firefox stops enforcing CT, because its log list may be outdated.

Usage:
    python scripts/update_firefox_ct_logs.py [output.json]
"""

import base64
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

import requests

SOURCE_URL = ("https://raw.githubusercontent.com/mozilla-firefox/firefox/refs/heads/release/"
              "security/ct/CTKnownLogs.h")
DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "trust", "data", "firefox-ct-logs.json"
)
EXPIRATION = re.compile(r"kCTExpirationTime\s*=\s*INT64_C\((\d+)\)")
# {"name", CTLogState::X, CTLogFormat::Y, timestamp, // ... operator index, // ... "key bytes", length},
LOG = re.compile(
    r'\{"(?P<name>[^"]+)",\s*CTLogState::(?P<state>\w+),\s*CTLogFormat::(?P<format>\w+),\s*'
    r'(?P<timestamp>\d+),[^\n]*\n\s*(?P<operator>\d+),[^\n]*\n(?P<key>(?:\s*"[^"]*")+),\s*(?P<length>\d+)\}'
)
OPERATOR = re.compile(r'\{"(?P<name>[^"]+)",\s*(?P<id>\d+)\}')


def _c_bytes(literals: str) -> bytes:
    """Decode concatenated C string literals made of \\xNN escapes."""
    data = bytearray()
    for literal in re.findall(r'"([^"]*)"', literals):
        for escape, char in re.findall(r"\\x([0-9a-fA-F]{2})|(.)", literal):
            data.append(int(escape, 16) if escape else ord(char))
    return bytes(data)


def parse(source: str) -> dict:
    """The expiration time and the logs of CTKnownLogs.h."""
    operators_table = source[source.index("kCTLogOperatorList[]"):]
    operators = [(m["name"], int(m["id"])) for m in OPERATOR.finditer(operators_table[:operators_table.index("};")])]
    logs = []
    for match in LOG.finditer(source[source.index("kCTLogList[]"):]):
        key = _c_bytes(match["key"])
        if len(key) != int(match["length"]):
            raise SystemExit(f"Unexpected key length for {match['name']}")
        operator_name, operator_id = operators[int(match["operator"])]
        logs.append({
            "name": match["name"],
            "log_id": base64.b64encode(hashlib.sha256(key).digest()).decode(),
            "state": match["state"],
            "format": match["format"],
            "timestamp_ms": int(match["timestamp"]),
            "operator": operator_name,
            "operator_id": operator_id,
            "key": base64.b64encode(key).decode(),
        })
    expiration = EXPIRATION.search(source)
    if not logs or not expiration:
        raise SystemExit("No CT logs found; the source format may have changed")
    expires = datetime.fromtimestamp(int(expiration.group(1)) / 1_000_000, timezone.utc)
    return {
        "source": SOURCE_URL,
        "expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "logs": logs,
    }


def main(output: str) -> None:
    response = requests.get(SOURCE_URL, timeout=60)
    response.raise_for_status()
    data = parse(response.text)
    with open(output, "w", encoding="utf-8") as out:
        json.dump(data, out, indent=1)
    print(f"Wrote {len(data['logs'])} CT logs to {output}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUTPUT)
