"""
HTTPS probe: requests the domain over HTTPS (following redirects) to find
out whether it supports HTTPS and where its redirects lead. It does not
retrieve or judge the certificate chain; that is done over a separate TLS
connection (src/fetch/tls.py).
"""

from urllib.parse import urlparse

import requests

from src.fetch.domain import DEFAULT_PORT

# Timeout of each request of the HTTPS probe. The probe only decides which
# error to report and follows redirects; the chain comes from the TLS handshake.
PROBE_TIMEOUT = 20

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

# Optional scheme, host name (labels of letters, digits, "-" and "_"; the
# top-level domain is letters or an internationalised "xn--" label) and
# optional port

# HTTPS probe: status codes that show the server speaks HTTPS, and status codes
# treated as "not reachable"
HTTPS_OK_STATUS = {400, 401, 403, 404, 415, 418, 429, 468, 470}
UNREACHABLE_STATUS = {307, 421, 428, 436}

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


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
    supported, final_host, final_port = _probe_https(host, port)
    if supported is not False or port != DEFAULT_PORT:
        return supported, final_host, final_port
    # Retry over HTTP to follow any HTTP -> HTTPS redirect
    try:
        response = requests.get(f"http://{host}", timeout=PROBE_TIMEOUT, allow_redirects=True,
                                verify=False, headers=HEADERS)
    except requests.exceptions.RequestException:
        return None, host, port
    if urlparse(response.url).scheme == "https" and response.status_code == 200:
        return (True, *host_port_from_url(response.url, host, port))
    return False, host, port


def _probe_https(host: str, port: int) -> tuple[bool | None, str, int]:
    """
    Request https://host:port, first with a browser User-Agent and then
    without one (some servers reject certain User-Agents). See
    supports_https for the return value.
    """
    with requests.Session() as session:
        for headers in (HEADERS, {}):
            try:
                # verify=False: only TLS support is probed here; the
                # certificate chain is validated separately.
                response = session.get(_https_url(host, port), timeout=PROBE_TIMEOUT,
                                       allow_redirects=True, verify=False, headers=headers)
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                # HTTPS failed: check whether the host answers over HTTP
                try:
                    response = session.get(f"http://{host}", timeout=PROBE_TIMEOUT, allow_redirects=True,
                                           verify=False, headers=headers)
                except requests.exceptions.RequestException:
                    continue
                return (False if response.status_code == 200 else None), host, port
            except requests.exceptions.RequestException:
                # e.g. too many redirects: the TLS handshake itself worked
                return True, host, port

            status = response.status_code
            if 200 <= status < 300:
                return (True, *host_port_from_url(response.url, host, port))
            if status in HTTPS_OK_STATUS:
                return True, host, port
            if status in UNREACHABLE_STATUS or status >= 500:
                return None, host, port
            return False, host, port
    return False, host, port
