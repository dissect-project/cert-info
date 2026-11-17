"""
Tests for how cert-info behaves toward the servers it contacts
(src/fetch/client.py): honest User-Agent, header-only HTTPS probe, and
backing off after 429/503. Network access is mocked.
"""

import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from src.fetch import client, https_probe, network

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


class FakeResponse:
    def __init__(self, status=200, url="https://example.com/", headers=None):
        self.status_code, self.url, self.headers = status, url, headers or {}
        self.body_read = False

    @property
    def is_redirect(self):
        return "Location" in self.headers and self.status_code in (301, 302, 303, 307, 308)

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def iter_content(self, size):
        self.body_read = True
        yield b"data"


class TestRetryAfter(unittest.TestCase):

    def test_seconds_and_dates(self):
        self.assertEqual(client.retry_after("120", NOW), timedelta(seconds=120))
        self.assertEqual(client.retry_after("Mon, 01 Jun 2026 12:05:00 GMT", NOW), timedelta(minutes=5))

    def test_missing_or_invalid_uses_default(self):
        self.assertEqual(client.retry_after(None, NOW), client.DEFAULT_BACK_OFF)
        self.assertEqual(client.retry_after("soon", NOW), client.DEFAULT_BACK_OFF)

    def test_bounds(self):
        self.assertEqual(client.retry_after("999999", NOW), client.MAX_BACK_OFF)
        self.assertEqual(client.retry_after("Mon, 01 Jun 2026 11:00:00 GMT", NOW), timedelta(0))

    def test_back_off_expires(self):
        back_off = client.BackOff()
        back_off.remember("host", 429, "30", "answer", now=NOW)
        self.assertEqual(back_off.waiting("host", NOW + timedelta(seconds=29)), (True, "answer"))
        self.assertEqual(back_off.waiting("host", NOW + timedelta(seconds=30)), (False, None))

    def test_only_429_and_503(self):
        back_off = client.BackOff()
        for status in (200, 403, 500, 502):
            back_off.remember("host", status, "30", "answer", now=NOW)
        self.assertEqual(back_off.waiting("host", NOW), (False, None))


class TestHttpsProbe(unittest.TestCase):

    def setUp(self):
        https_probe._back_off.clear()

    def probe(self, *responses, internal=()):
        """Probe example.com; hosts in `internal` resolve to a private address."""
        calls = []

        def get(session, url, **kwargs):
            calls.append(dict(kwargs, url=url))
            return responses[len(calls) - 1]

        def addresses(host, port):
            if host in internal:
                raise network.AddressNotAllowed("address not allowed")
            return ["192.0.2.1"]
        with mock.patch("requests.Session.get", new=get), \
                mock.patch.object(https_probe, "_public_addresses", side_effect=addresses):
            result = https_probe.supports_https("example.com")
        return result, calls

    def test_honest_user_agent_and_no_body(self):
        response = FakeResponse(200, "https://www.example.com/")
        result, calls = self.probe(response)
        self.assertEqual(result, (True, "www.example.com", 443))
        self.assertEqual(calls[0]["headers"]["User-Agent"], client.USER_AGENT)
        self.assertTrue(calls[0]["stream"])
        self.assertFalse(response.body_read)
        self.assertNotIn("Chrome", client.USER_AGENT)

    def test_rate_limited_server_is_not_probed_again(self):
        """After 429 with Retry-After, the previous answer is reused until the delay passes."""
        result, calls = self.probe(FakeResponse(429, headers={"Retry-After": "120"}))
        self.assertEqual((result, len(calls)), ((True, "example.com", 443), 1))
        again, calls = self.probe()
        self.assertEqual((again, calls), (result, []))

    def test_unavailable_server(self):
        result, _ = self.probe(FakeResponse(503))
        self.assertEqual(result, (None, "example.com", 443))
        self.assertEqual(self.probe()[1], [])

    def test_redirects_are_followed(self):
        result, calls = self.probe(FakeResponse(301, "https://example.com/", {"Location": "https://www.example.com/a"}),
                                   FakeResponse(200, "https://www.example.com/a"))
        self.assertEqual(result, (True, "www.example.com", 443))
        self.assertEqual([c["url"] for c in calls], ["https://example.com", "https://www.example.com/a"])
        self.assertFalse(any(c["allow_redirects"] for c in calls))

    def test_redirect_to_internal_address_is_not_followed(self):
        result, calls = self.probe(FakeResponse(302, "https://example.com/", {"Location": "http://169.254.169.254/"}),
                                   internal={"169.254.169.254"})
        self.assertEqual(result, (True, "example.com", 443))
        self.assertEqual(len(calls), 1)

    def test_redirect_to_other_scheme_is_not_followed(self):
        result, calls = self.probe(FakeResponse(302, "https://example.com/", {"Location": "file:///etc/passwd"}))
        self.assertEqual((result, len(calls)), ((True, "example.com", 443), 1))

    def test_internal_domain_is_not_requested(self):
        result, calls = self.probe(internal={"example.com"})
        self.assertEqual((result, calls), ((None, "example.com", 443), []))

    def test_other_statuses_do_not_back_off(self):
        self.probe(FakeResponse(200))
        _, calls = self.probe(FakeResponse(200))
        self.assertEqual(len(calls), 1)


class TestCertificateUrls(unittest.TestCase):
    """CRL, OCSP and AIA downloads."""

    def setUp(self):
        network._back_off.clear()

    def fetch(self, response):
        requests_made = []

        def request(method, url, **kwargs):
            requests_made.append(kwargs["headers"])
            return response
        with mock.patch.object(network, "_public_addresses", return_value=["192.0.2.1"]), \
                mock.patch("requests.request", side_effect=request):
            try:
                return network.fetch("http://crl.example/ca.crl"), requests_made
            except network.FetchError as e:
                return str(e), requests_made

    def test_user_agent(self):
        body, headers = self.fetch(FakeResponse(200))
        self.assertEqual(body, b"data")
        self.assertEqual(headers[0]["User-Agent"], client.USER_AGENT)

    def test_rate_limited_server_is_not_contacted_again(self):
        error, _ = self.fetch(FakeResponse(429, headers={"Retry-After": "60"}))
        self.assertEqual(error, "HTTP status 429")
        error, requests_made = self.fetch(FakeResponse(200))
        self.assertEqual((error, requests_made), ("server asked to retry later", []))


class TestInternalDomains(unittest.TestCase):
    """A domain resolving to an internal address is never contacted, even with force."""

    def test_rejected_before_any_connection(self):
        from src import certificate_info
        with mock.patch.object(certificate_info, "_public_addresses",
                               side_effect=network.AddressNotAllowed("address not allowed")), \
                mock.patch.object(certificate_info, "is_reachable") as reachable, \
                mock.patch.object(certificate_info, "fetch_handshake") as handshake:
            result = certificate_info.CertificateInformation().analyze("internal.example", force=True)
        self.assertEqual(result, {"status": "error", "error": "Domain resolves to a non-public address."})
        reachable.assert_not_called()
        handshake.assert_not_called()


class TestDnsRebinding(unittest.TestCase):
    """
    Connections go to the address checked when they are opened: a DNS answer
    that is public at check time and internal afterwards is never used.
    """

    @staticmethod
    def rebinding_dns():
        """getaddrinfo answering a public address first, then loopback."""
        answers = iter(["8.8.8.8"])

        def getaddrinfo(host, port, *args, **kwargs):
            return [(2, 1, 6, "", (next(answers, "127.0.0.1"), port))]
        return getaddrinfo

    def test_requests_connect_to_checked_address(self):
        connected = []

        def create_connection(address, *args, **kwargs):
            connected.append(address)
            raise OSError("stop here")
        with mock.patch("socket.getaddrinfo", side_effect=self.rebinding_dns()), \
                mock.patch.object(network.urllib3_connection, "create_connection", side_effect=create_connection), \
                network.public_only_session() as session:
            with self.assertRaises(network.requests.ConnectionError):
                session.get("https://rebind.example/", timeout=1)
            with self.assertRaises(network.requests.ConnectionError):
                session.get("https://rebind.example/", timeout=1)
        # First connection to the checked public address; the second lookup
        # answered loopback, so no connection was made at all
        self.assertEqual(connected, [("8.8.8.8", 443)])

    def test_openssl_connects_to_checked_address_with_sni(self):
        from src.fetch import tls
        result = mock.Mock(stdout="")
        with mock.patch.object(tls, "_public_addresses", return_value=["192.0.2.1"]), \
                mock.patch.object(tls, "firefox_tls_args", return_value=[]), \
                mock.patch("subprocess.run", return_value=result) as run:
            tls.fetch_handshake("example.com")
        cmd = run.call_args_list[0].args[0]
        self.assertEqual(cmd[cmd.index("-connect") + 1], "192.0.2.1:443")
        self.assertEqual(cmd[cmd.index("-servername") + 1], "example.com")

    def test_openssl_not_run_for_internal_address(self):
        from src.fetch import tls
        with mock.patch.object(tls, "_public_addresses", side_effect=network.AddressNotAllowed("no")), \
                mock.patch("subprocess.run") as run:
            self.assertEqual(tls.fetch_handshake("example.com").certificates, [])
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
