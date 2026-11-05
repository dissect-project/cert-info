"""
A small thread-safe in-memory cache with per-entry expiry and a size limit,
used for downloaded CRLs and OCSP responses (see src/validation/revocation.py).

Each uvicorn worker process has its own cache.
"""

import threading
from collections import OrderedDict
from datetime import datetime


class ExpiringCache:
    """
    Entries expire at a time given when they are stored. When the total size
    exceeds max_bytes, the least recently used entries are dropped.
    """

    def __init__(self, max_bytes: int):
        self.max_bytes = max_bytes
        self._entries = OrderedDict()   # key -> (value, size, expires)
        self._size = 0
        self._lock = threading.Lock()

    def get(self, key, now: datetime):
        """The value stored for key, or None if there is none or it has expired."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            value, _, expires = entry
            if now >= expires:
                self._remove(key)
                return None
            self._entries.move_to_end(key)
            return value

    def put(self, key, value, size: int, expires: datetime, now: datetime) -> None:
        """Store a value until `expires`. Values larger than the whole cache are not stored."""
        if expires <= now or size > self.max_bytes:
            return
        with self._lock:
            if key in self._entries:
                self._remove(key)
            self._entries[key] = (value, size, expires)
            self._size += size
            while self._size > self.max_bytes:
                self._remove(next(iter(self._entries)))

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._size = 0

    def __len__(self) -> int:
        return len(self._entries)

    def _remove(self, key) -> None:
        _, size, _ = self._entries.pop(key)
        self._size -= size
