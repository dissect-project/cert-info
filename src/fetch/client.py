"""
How cert-info presents itself to the servers it contacts, and how it backs
off when they ask it to.

- Every HTTP request (the HTTPS probe, and CRL, OCSP and AIA downloads) sends
  an honest User-Agent naming cert-info and where to learn about it. Set
  CERTINFO_USER_AGENT to change it (e.g. to add a contact page for your
  deployment).
- When a server answers 429 (Too Many Requests) or 503 (Service Unavailable),
  it is not contacted again over HTTP until its Retry-After delay has passed
  (60 seconds if it gives none, at most one hour). Meanwhile the previous
  answer is reused. TLS handshakes, which retrieve the certificates, are not
  affected.
"""

import os
import threading
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

VERSION = "0.1.0"   # keep in step with pyproject.toml
PROJECT_URL = "https://github.com/dissect-project/cert_info"
USER_AGENT = os.environ.get("CERTINFO_USER_AGENT") or f"cert-info/{VERSION} (+{PROJECT_URL})"

BACK_OFF_STATUS = {429, 503}
DEFAULT_BACK_OFF = timedelta(seconds=60)
MAX_BACK_OFF = timedelta(hours=1)


def retry_after(value: str | None, now: datetime) -> timedelta:
    """The delay a Retry-After header asks for (seconds or an HTTP date), within bounds."""
    delay = DEFAULT_BACK_OFF
    if value:
        value = value.strip()
        try:
            if value.isdigit():
                delay = timedelta(seconds=int(value))
            else:
                date = parsedate_to_datetime(value)
                if date.tzinfo is None:
                    date = date.replace(tzinfo=timezone.utc)
                delay = date - now
        except (TypeError, ValueError, OverflowError):
            delay = DEFAULT_BACK_OFF
    return min(max(delay, timedelta(0)), MAX_BACK_OFF)


class BackOff:
    """Servers that asked to be left alone, and the answer to reuse meanwhile."""

    def __init__(self):
        self._until = {}   # key -> (until, remembered answer)
        self._lock = threading.Lock()

    def remember(self, key, status: int, retry_after_header: str | None, answer,
                 now: datetime | None = None) -> None:
        """Record a 429 or 503 answer (other statuses are ignored)."""
        if status not in BACK_OFF_STATUS:
            return
        now = now or datetime.now(timezone.utc)
        delay = retry_after(retry_after_header, now)
        if delay > timedelta(0):
            with self._lock:
                self._until[key] = (now + delay, answer)

    def waiting(self, key, now: datetime | None = None) -> tuple[bool, object]:
        """(True, remembered answer) while the server asked to wait, else (False, None)."""
        now = now or datetime.now(timezone.utc)
        with self._lock:
            entry = self._until.get(key)
            if entry is None:
                return False, None
            until, answer = entry
            if now >= until:
                del self._until[key]
                return False, None
            return True, answer

    def clear(self) -> None:
        with self._lock:
            self._until.clear()
