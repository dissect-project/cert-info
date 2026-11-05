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

    def probe(self, *responses):
        calls = []

        def get(session, url, **kwargs):
            calls.append(kwargs)
            return responses[len(calls) - 1]
        with mock.patch("requests.Session.get", new=get):
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


if __name__ == "__main__":
    unittest.main()
