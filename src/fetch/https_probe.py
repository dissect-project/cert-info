"""
HTTPS probe: requests the domain over HTTPS (following redirects) to find
out whether it supports HTTPS and where its redirects lead. It does not
retrieve or judge the certificate chain; that is done over a separate TLS
connection (src/fetch/tls.py).

Only the status and headers of each response are used: page bodies are not
downloaded. Requests identify cert-info honestly, and a server that answers
429 or 503 is not probed again until its Retry-After delay has passed (see
src/fetch/client.py).

Like the certificate URL downloads (src/fetch/network.py), the probe only
contacts public IP addresses, so a domain (or a redirect) cannot make
cert-info reach internal systems (SSRF): redirects are followed one at a
time and each host is checked before it is requested, and the connection
itself goes to an address checked when it is opened (no DNS rebinding).
"""

from urllib.parse import urljoin, urlparse

import requests

from src.fetch.client import USER_AGENT, BackOff
from src.fetch.domain import DEFAULT_PORT
from src.fetch.network import AddressNotAllowed, FetchError, _public_addresses, public_only_session

# Timeout of each request of the HTTPS probe. The probe only decides which
# error to report and follows redirects; the chain comes from the TLS handshake.
PROBE_TIMEOUT = 20
# Redirects followed by the probe (the requests library's default)
MAX_REDIRECTS = 30

HEADERS = {"User-Agent": USER_AGENT}
# Probe answers to reuse while a server asked cert-info to wait
_back_off = BackOff()

# HTTPS probe: status codes that show the server speaks HTTPS, and status codes
# treated as "not reachable"
HTTPS_OK_STATUS = {400, 401, 403, 404, 415, 418, 429, 468, 470}
UNREACHABLE_STATUS = {307, 421, 428, 436}

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


class BlockedUrl(requests.exceptions.RequestException):
    """A redirect to a non-public address or to a scheme other than http(s)."""


def _check_url(url: str) -> None:
    """
    Raise BlockedUrl unless the URL is http(s) and its host resolves only to
    public addresses; raise ConnectionError if the host does not resolve.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise BlockedUrl(url)
    try:
        port = parsed.port or (DEFAULT_PORT if parsed.scheme == "https" else 80)
        _public_addresses(parsed.hostname, port)
    except AddressNotAllowed as e:
        raise BlockedUrl(url) from e
    except (FetchError, ValueError) as e:
        raise requests.exceptions.ConnectionError(url) from e


def _get(session, url: str, headers: dict):
    """
    GET the URL with redirects followed one at a time, checking each URL with
    _check_url before requesting it. The final response is streamed (its body
    is not read) and must be closed by the caller.
    """
    for _ in range(MAX_REDIRECTS + 1):
        _check_url(url)
        response = session.get(url, timeout=PROBE_TIMEOUT, allow_redirects=False,
                               verify=False, headers=headers, stream=True)
        if not response.is_redirect:
            return response
        url = urljoin(response.url, response.headers["Location"])
        response.close()
    raise requests.exceptions.TooManyRedirects(url)


def _https_url(host: str, port: int) -> str:
    """https URL for host and port, omitting the port when it is 443."""
    return f"https://{host}" if port == DEFAULT_PORT else f"https://{host}:{port}"


def host_port_from_url(url: str, host: str, port: int) -> tuple[str, int]:
    """
    Host and TLS port of a final (redirected) URL. For an https URL this is its
    port (443 if none); for a redirect down to http, the host is kept and the
    TLS port is 443. Defaults to the given host and port if the URL has no host.
    """
    parsed = urlparse(url)
    if not parsed.hostname:
        return host, port
    if parsed.scheme != "https":
        return parsed.hostname, DEFAULT_PORT
    return parsed.hostname, parsed.port or DEFAULT_PORT


def supports_https(host: str, port: int = DEFAULT_PORT) -> tuple[bool | None, str, int]:
    """
    Probe the server over HTTPS, following redirects.

    Returns:
        tuple: (supported, final_host, final_port)
            supported: True if HTTPS works, False if it does not, None if
                the server could not be reached.
            final_host, final_port: where the redirects led, when the
                probe succeeded with a 2xx response; the given host and
                port otherwise.
    """
    waiting, answer = _back_off.waiting((host, port))
    if waiting:
        return answer
    try:
        _check_url(_https_url(host, port))
    except requests.exceptions.RequestException:
        return None, host, port     # internal address or no DNS: not reachable
    supported, final_host, final_port = _probe_https(host, port)
    if supported is not False or port != DEFAULT_PORT:
        return supported, final_host, final_port
    # Retry over HTTP to follow any HTTP -> HTTPS redirect
    try:
        with public_only_session() as session, _get(session, f"http://{host}", HEADERS) as response:
            if urlparse(response.url).scheme == "https" and response.status_code == 200:
                return (True, *host_port_from_url(response.url, host, port))
            return _answer(host, port, response, (False, host, port))
    except requests.exceptions.RequestException:
        return None, host, port


def _answer(host: str, port: int, response, answer: tuple) -> tuple:
    """Return the probe's answer, remembering it if the server asked to wait (429/503)."""
    _back_off.remember((host, port), response.status_code, response.headers.get("Retry-After"), answer)
    return answer


def _probe_https(host: str, port: int) -> tuple[bool | None, str, int]:
    """
    Request https://host:port, first with cert-info's User-Agent and then
    with the requests library's default one (some servers reject certain
    User-Agents). Responses are streamed and closed without reading their
    body. See supports_https for the return value.
    """
    with public_only_session() as session:
        for headers in (HEADERS, {}):
            try:
                # verify=False: only TLS support is probed here; the
                # certificate chain is validated separately.
                with _get(session, _https_url(host, port), headers) as response:
                    return _answer(host, port, response, _classify(response, host, port))
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                # HTTPS failed: check whether the host answers over HTTP
                try:
                    with _get(session, f"http://{host}", headers) as response:
                        answer = (False if response.status_code == 200 else None), host, port
                        return _answer(host, port, response, answer)
                except requests.exceptions.RequestException:
                    continue
            except requests.exceptions.RequestException:
                # e.g. too many redirects, or a redirect to an internal
                # address (not followed): the TLS handshake itself worked
                return True, host, port
    return False, host, port


def _classify(response, host: str, port: int) -> tuple[bool | None, str, int]:
    """The probe's answer for the final HTTPS response."""
    status = response.status_code
    if 200 <= status < 300:
        return (True, *host_port_from_url(response.url, host, port))
    if status in HTTPS_OK_STATUS:
        return True, host, port
    if status in UNREACHABLE_STATUS or status >= 500:
        return None, host, port
    return False, host, port
