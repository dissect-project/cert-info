"""
Refresh all the trust data cert-info uses, from the current Firefox release:

    src/trust/data/mozilla-certs.pem, src/trust/data/mozilla-distrust.csv   update_mozilla_roots.py
    src/trust/data/mozilla-intermediates.pem                      update_mozilla_intermediates.py
    src/trust/data/firefox-ev-roots.csv                           update_firefox_ev_roots.py
    src/trust/data/mozilla-onecrl.json                            update_mozilla_onecrl.py
    src/trust/data/firefox-ct-logs.json                           update_firefox_ct_logs.py
    src/trust/data/firefox-pins.json                              update_firefox_pins.py

Each file is written to a temporary file first and only replaces the current
one if its download succeeded, so a failure leaves the previous data in place.
Exits with status 1 if any update failed.

Usage:
    python scripts/update_trust_data.py
"""

import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import update_firefox_ct_logs  # noqa: E402
import update_firefox_ev_roots  # noqa: E402
import update_firefox_pins  # noqa: E402
import update_mozilla_intermediates  # noqa: E402
import update_mozilla_onecrl  # noqa: E402
import update_mozilla_roots  # noqa: E402

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "trust", "data")


def _path(name: str) -> str:
    return os.path.join(DATA_DIR, name)


# (description, function, output files)
UPDATES = [
    ("Mozilla roots and distrust dates", update_mozilla_roots.main,
     ["mozilla-certs.pem", "mozilla-distrust.csv"]),
    ("Firefox preloaded intermediates", update_mozilla_intermediates.main, ["mozilla-intermediates.pem"]),
    ("Firefox EV roots", update_firefox_ev_roots.main, ["firefox-ev-roots.csv"]),
    ("OneCRL", update_mozilla_onecrl.main, ["mozilla-onecrl.json"]),
    ("Firefox CT logs", update_firefox_ct_logs.main, ["firefox-ct-logs.json"]),
    ("Firefox static key pins", update_firefox_pins.main, ["firefox-pins.json"]),
]


def main() -> int:
    failed = []
    for description, update, outputs in UPDATES:
        temporary = [_path(name) + ".new" for name in outputs]
        try:
            update(*temporary)
            for name, new in zip(outputs, temporary):
                os.replace(new, _path(name))
        except (Exception, SystemExit):
            traceback.print_exc()
            print(f"WARNING: could not update {description}; keeping the current data", file=sys.stderr)
            failed.append(description)
            for new in temporary:
                if os.path.exists(new):
                    os.remove(new)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
