"""
Fetching URLs found inside certificates (AIA caIssuers, CRL distribution
points, OCSP responders).

These URLs come from certificates presented by the analysed server, which may
be self-signed and fully controlled by whoever runs that server. To stop the
service being used to reach internal systems (SSRF), every request:

- must be plain http:// (the CA/Browser Forum requires http for these URLs);
- may only go to a public IP address, checked after DNS resolution, and the
  connection is made to that checked address so DNS cannot change in between;
- does not follow redirects;
- is limited in size and time;
- identifies cert-info (User-Agent), and is not sent to a server that
  answered 429 or 503 until its Retry-After delay has passed.
"""

import ipaddress
import socket
from urllib.parse import urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NewConnectionError
from urllib3.util import connection as urllib3_connection

from src.fetch.client import USER_AGENT, BackOff

MAX_RESPONSE_BYTES = 20 * 1024 * 1024  # large CRLs can be several MB
TIMEOUT = 10
# Servers (by host name) that asked cert-info to wait (429/503 Retry-After)
_back_off = BackOff()
MAX_ADDRESSES = 3  # addresses tried when a connection fails (e.g. no IPv6 route)


class FetchError(Exception):
    """The URL could not be fetched. The message is safe to show to users."""


class AddressNotAllowed(FetchError):
    """The host resolves to an address that is not public (internal, loopback, ...)."""


def _public_addresses(host: str, port: int) -> list:
    """Resolve host and return its addresses, if every address is public."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as e:
        raise FetchError("host not found") from e
    addresses = [info[4][0] for info in infos]
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%")[0])
        if not ip.is_global or ip.is_multicast:
            raise AddressNotAllowed("address not allowed")
    return list(dict.fromkeys(addresses))


class _PublicOnly:
    """
    Connection mixin: the host is resolved, every address checked to be
    public, and the socket connected to a checked address, in one step. The
    host is not resolved again in between, so a DNS answer that changes after
    the check (DNS rebinding) cannot lead to an internal address. TLS (SNI,
    certificate) and the Host header still use the host name.
    """

    def _new_conn(self):
        try:
            addresses = _public_addresses(self._dns_host, self.port)
        except FetchError as e:
            raise NewConnectionError(self, f"{self.host}: {e}") from e
        error = None
        for address in addresses[:MAX_ADDRESSES]:
            try:
                return urllib3_connection.create_connection(
                    (address, self.port), self.timeout,
                    source_address=self.source_address, socket_options=self.socket_options)
            except socket.timeout as e:
                error = ConnectTimeoutError(self, f"Connection to {self.host} timed out.")
                error.__cause__ = e
            except OSError as e:
                error = NewConnectionError(self, f"Failed to establish a new connection: {e}")
                error.__cause__ = e
        raise error


class _PublicHTTPConnection(_PublicOnly, HTTPConnection):
    pass


class _PublicHTTPSConnection(_PublicOnly, HTTPSConnection):
    pass


class _PublicHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _PublicHTTPConnection


class _PublicHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _PublicHTTPSConnection


class PublicOnlyAdapter(HTTPAdapter):
    """requests adapter whose connections only go to public IP addresses (see _PublicOnly)."""

    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {"http": _PublicHTTPConnectionPool,
                                                   "https": _PublicHTTPSConnectionPool}


def public_only_session() -> requests.Session:
    """
    A requests Session that only connects to public IP addresses. Proxy
    settings from the environment are ignored: the check is about the server
    itself, which a proxy connection would bypass.
    """
    session = requests.Session()
    session.trust_env = False
    adapter = PublicOnlyAdapter()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def fetch(url: str, data: bytes | None = None, content_type: str | None = None) -> bytes:
    """
    GET (or POST, when data is given) a certificate-related http:// URL.

    Returns:
        bytes: The response body.

    Raises:
        FetchError: If the URL is not allowed or the request fails.
    """
    parsed = urlparse(url)
    if parsed.scheme != "http" or not parsed.hostname:
        raise FetchError("only http:// URLs are fetched")
    port = parsed.port or 80
    host_header = parsed.hostname if parsed.port in (None, 80) else f"{parsed.hostname}:{parsed.port}"
    waiting, _ = _back_off.waiting(parsed.hostname)
    if waiting:
        raise FetchError("server asked to retry later")
    headers = {"Host": host_header, "User-Agent": USER_AGENT}
    if content_type:
        headers["Content-Type"] = content_type
    method = "POST" if data is not None else "GET"
    for address in _public_addresses(parsed.hostname, port)[:MAX_ADDRESSES]:
        # Connect to the checked address; keep the original host in the Host header
        netloc = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
        pinned = urlunparse(parsed._replace(netloc=netloc))
        try:
            return _request(method, pinned, data, headers, parsed.hostname)
        except requests.ConnectionError:
            continue  # try the next address
        except requests.RequestException as e:
            raise FetchError("download failed") from e
    raise FetchError("download failed")


def _request(method: str, url: str, data: bytes | None, headers: dict, hostname: str) -> bytes:
    """One request, without redirects and with a size limit."""
    with requests.request(method, url, data=data, headers=headers, timeout=TIMEOUT,
                          allow_redirects=False, stream=True) as response:
        _back_off.remember(hostname, response.status_code, response.headers.get("Retry-After"), None)
        if response.status_code != 200:
            raise FetchError(f"HTTP status {response.status_code}")
        body = bytearray()
        for chunk in response.iter_content(64 * 1024):
            body.extend(chunk)
            if len(body) > MAX_RESPONSE_BYTES:
                raise FetchError("response too large")
        return bytes(body)
