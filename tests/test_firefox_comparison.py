"""
Compares the chains cert-info builds with the chains Firefox builds, for the
top domains of a Tranco list (https://tranco-list.eu).

This test needs Firefox, network access and Selenium (requirements-dev.txt),
and takes about 1-2 minutes for 250 domains, so it only runs on request:

    CERTINFO_FIREFOX_TEST=1 python -m unittest tests.test_firefox_comparison -v

Environment variables:
    CERTINFO_FIREFOX_TEST    "1" to run the test
    CERTINFO_TRANCO_LIST     Tranco list ID (default: JZPGY, list of 2026-11-04;
                             fixed so that runs are comparable)
    CERTINFO_TRANCO_TOP      Number of domains (default: 250)
    CERTINFO_FIREFOX_BINARY  Path to the Firefox executable (default: found
                             automatically)
    CERTINFO_FIREFOX_REPORT  Where to write the JSON report
                             (default: firefox_comparison.json)
    CERTINFO_FIREFOX_CONCURRENCY  Requests Firefox makes at the same time
                             (default: 24)

For every domain, Firefox requests https://<domain>/ (following redirects, as
a page load does) from its privileged context, many domains at a time; the
request stops as soon as the response headers arrive. The test then reads,
from the connection's security information, the certificates the server sent
(handshakeCertificates) and the chain Firefox built (succeededCertChain). This
is Firefox's own certificate verification, without rendering pages. Firefox's
preloaded intermediates are enabled and downloaded first, as in a normal
Firefox (automation disables them by default).

Two comparisons are made:

    path building  cert-info's PathBuilder is given exactly the certificates
                   Firefox received and must build exactly Firefox's chain.
                   When Firefox rejects the chain as untrusted, cert-info must
                   not find a chain Firefox would accept either.
    end to end     cert-info fetches the certificates itself (as the API does)
                   for the host Firefox ended on. Servers can send different
                   certificates on different connections (load balancers,
                   RSA and ECDSA certificates), so chains are only required to
                   match when both connections received the same leaf.
"""

import base64
import csv
import io
import json
import os
import shutil
import sys
import unittest
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from src.chain.path_builder import PathBuilder
from src.fetch.tls import fetch_server_certificates
from src.validation.chain_validator import ChainValidator

ENABLED = os.environ.get("CERTINFO_FIREFOX_TEST") == "1"
TRANCO_LIST = os.environ.get("CERTINFO_TRANCO_LIST", "JZPGY")
TOP = int(os.environ.get("CERTINFO_TRANCO_TOP", "250"))
REPORT = os.environ.get("CERTINFO_FIREFOX_REPORT", "firefox_comparison.json")
CONCURRENCY = int(os.environ.get("CERTINFO_FIREFOX_CONCURRENCY", "24"))
REQUEST_TIMEOUT_MS = 15000
OUR_FETCH_WORKERS = 16

# nsITransportSecurityInfo.overridableErrorCategory
FIREFOX_ERRORS = {0: None, 1: "untrusted", 2: "domain mismatch", 3: "expired or not yet valid"}

# Chrome-context script: request https://<domain>/ for many domains at a time
# and report what Firefox knows about each final connection
PROBE_JS = """
const [domains, concurrency, timeoutMs, done] = arguments;
const der = list => (list || []).map(cert => cert.getBase64DERString());

function probe(domain) {
    return new Promise(resolve => {
        const xhr = new XMLHttpRequest();
        let finished = false;
        const finish = outcome => {
            if (finished) return;
            finished = true;
            let info = null, url = null;
            try { info = xhr.channel.securityInfo; } catch (e) {}
            try { url = xhr.channel.URI.spec; } catch (e) {}
            resolve({ domain, outcome, url,
                      handshake: info ? der(info.handshakeCertificates) : [],
                      built: info ? der(info.succeededCertChain) : [],
                      error_category: info ? info.overridableErrorCategory : null });
            xhr.abort();
        };
        xhr.open("GET", "https://" + domain + "/");
        xhr.timeout = timeoutMs;
        // Stop at the response headers: redirects are followed, bodies are not downloaded
        xhr.onreadystatechange = () => { if (xhr.readyState >= 2) finish("response"); };
        xhr.onerror = () => finish("error");
        xhr.ontimeout = () => finish("timeout");
        xhr.send();
    });
}

(async () => {
    const results = [];
    let next = 0;
    async function worker() {
        while (next < domains.length) {
            const index = next++;
            results[index] = await probe(domains[index]);
        }
    }
    await Promise.all(Array.from({ length: concurrency }, worker));
    return results;
})().then(done, error => done({ error: String(error) }));
"""

# Chrome-context script: download Firefox's preloaded intermediates now
SYNC_INTERMEDIATES_JS = """
const done = arguments[arguments.length - 1];
(async () => {
    const { RemoteSettings } = ChromeUtils.importESModule(
        "resource://services-settings/remote-settings.sys.mjs");
    const topic = "remote-security-settings:intermediates-updated";
    const updated = new Promise(resolve => Services.obs.addObserver(function observer() {
        Services.obs.removeObserver(observer, topic);
        resolve(true);
    }, topic));
    await RemoteSettings.pollChanges();
    const finished = await Promise.race(
        [updated, new Promise(resolve => setTimeout(() => resolve(false), 240000))]);
    const records = await RemoteSettings("intermediates", { bucketName: "security-state" })
        .get({ syncIfEmpty: false });
    return { finished, records: records.length,
             imported: records.filter(r => r.cert_import_complete).length };
})().then(done, error => done({ error: String(error) }));
"""


def _load_der(b64: str) -> x509.Certificate:
    return x509.load_der_x509_certificate(base64.b64decode(b64))


def _fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _describe(certs: list) -> list:
    """Subject and fingerprint of each certificate, for the report."""
    return [{"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
             "fingerprint_SHA256": _fingerprint(c)} for c in certs]


def tranco_domains(list_id: str, top: int) -> list:
    """The first `top` domains of a Tranco list."""
    url = f"https://tranco-list.eu/download/{list_id}/{max(top, 1000)}"
    response = requests.get(url, timeout=120)
    response.raise_for_status()
    rows = csv.reader(io.StringIO(response.text))
    return [domain for _, domain in rows][:top]


def find_firefox() -> str:
    """Path to the Firefox executable."""
    candidates = [
        os.environ.get("CERTINFO_FIREFOX_BINARY"),
        shutil.which("firefox"),
        "/Applications/Firefox.app/Contents/MacOS/firefox",
        r"C:\Program Files\Mozilla Firefox\firefox.exe",
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    raise unittest.SkipTest("Firefox not found; set CERTINFO_FIREFOX_BINARY")


class Firefox:
    """A headless Firefox that reports the certificate chains it builds."""

    def __init__(self):
        from selenium import webdriver
        options = webdriver.FirefoxOptions()
        options.add_argument("-headless")
        options.binary_location = find_firefox()
        # Automation disables the preloaded intermediates; a normal Firefox uses them
        options.set_preference("security.remote_settings.intermediates.enabled", True)
        # Chrome-context scripts need system access
        service = webdriver.FirefoxService(service_args=["--allow-system-access"])
        self.driver = webdriver.Firefox(options=options, service=service)
        self.driver.set_script_timeout(900)
        self.version = self.driver.capabilities.get("browserVersion")

    def _chrome_script(self, script: str, *args):
        with self.driver.context(self.driver.CONTEXT_CHROME):
            result = self.driver.execute_async_script(script, *args)
        if isinstance(result, dict) and "error" in result:
            raise RuntimeError(result["error"])
        return result

    def sync_intermediates(self) -> dict:
        return self._chrome_script(SYNC_INTERMEDIATES_JS)

    def probe(self, domains: list) -> list:
        """What Firefox saw for each domain (same order as domains)."""
        return [self._parse(raw) for raw in self._chrome_script(
            PROBE_JS, domains, CONCURRENCY, REQUEST_TIMEOUT_MS)]

    @staticmethod
    def _parse(raw: dict) -> dict:
        url = urlparse(raw["url"] or "")
        if url.scheme != "https" or not raw["handshake"]:
            return {"status": "no_tls", "error": raw["outcome"], "url": raw["url"]}
        return {
            "status": "built" if raw["built"] else "rejected",
            "host": url.hostname,
            "port": url.port or 443,
            "handshake": [_load_der(c) for c in raw["handshake"]],
            "built": [_load_der(c) for c in raw["built"]],
            "error": FIREFOX_ERRORS.get(raw["error_category"], str(raw["error_category"])),
        }

    def quit(self):
        self.driver.quit()


def fetch_our_chain(host: str, port: int) -> list:
    """The chain cert-info builds end to end (TLS fetch + path building)."""
    pems = fetch_server_certificates(host, port)
    chain, _, _, _ = ChainValidator.build_chain(pems, hostname=host)
    return [entry["cert"] for entry in chain]


def compare(domain: str, firefox: dict, our_live) -> dict:
    """Compare one domain; our_live is a Future with our end-to-end chain."""
    result = {"domain": domain, "firefox_status": firefox["status"]}
    if firefox["status"] == "no_tls":
        result["firefox_error"] = firefox.get("error")
        return result
    result.update(host=firefox["host"], firefox_error=firefox["error"],
                  firefox_handshake=_describe(firefox["handshake"]),
                  firefox_chain=_describe(firefox["built"]))

    # Path building from exactly the certificates Firefox received
    built = PathBuilder.mozilla(aia_fetcher=None).build(firefox["handshake"])
    ours = [cert for cert, _ in built.path]
    result["path_building"] = {
        "chain": _describe(ours),
        "origins": [origin for _, origin in built.path],
        "strict": built.strict,
        "matches": built.strict and [_fingerprint(c) for c in ours] == [_fingerprint(c) for c in firefox["built"]],
    }

    # End to end
    try:
        live = our_live.result()
    except Exception as error:
        live, result["end_to_end_error"] = [], f"{type(error).__name__}: {error}"
    same_leaf = bool(live and firefox["handshake"]) and \
        _fingerprint(live[0]) == _fingerprint(firefox["handshake"][0])
    result["end_to_end"] = {
        "chain": _describe(live),
        "same_leaf": same_leaf,
        "matches": [_fingerprint(c) for c in live] == [_fingerprint(c) for c in firefox["built"]],
    }
    return result


def run_comparison(domains: list) -> dict:
    """Probe every domain in Firefox and compare with cert-info."""
    firefox = Firefox()
    report = {
        "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "firefox_version": firefox.version,
        "tranco_list": TRANCO_LIST,
        "domains": len(domains),
    }
    try:
        report["intermediates_sync"] = firefox.sync_intermediates()
        seen_by_firefox = firefox.probe(domains)
    finally:
        firefox.quit()
    print(f"Firefox: {Counter(seen['status'] for seen in seen_by_firefox)}", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=OUR_FETCH_WORKERS) as pool:
        ours = [pool.submit(fetch_our_chain, seen["host"], seen["port"])
                if seen["status"] != "no_tls" else None for seen in seen_by_firefox]
        report["results"] = [compare(domain, seen, live)
                             for domain, seen, live in zip(domains, seen_by_firefox, ours)]
    report["summary"] = summarise(report["results"])
    return report


def summarise(results: list) -> dict:
    """Counts per outcome."""
    summary = Counter()
    for r in results:
        summary[f"firefox_{r['firefox_status']}"] += 1
        if r["firefox_status"] == "no_tls":
            continue
        path = r["path_building"]
        if r["firefox_status"] == "built":
            summary["path_building_match" if path["matches"] else "path_building_MISMATCH"] += 1
            e2e = r["end_to_end"]
            if not e2e["same_leaf"]:
                summary["end_to_end_different_leaf"] += 1
            else:
                summary["end_to_end_match" if e2e["matches"] else "end_to_end_MISMATCH"] += 1
        elif r["firefox_error"] == "untrusted":
            summary["rejection_match" if not path["strict"] else "rejection_MISMATCH"] += 1
        else:
            summary[f"firefox_rejected_{r['firefox_error']}"] += 1
    return dict(sorted(summary.items()))


@unittest.skipUnless(ENABLED, "set CERTINFO_FIREFOX_TEST=1 to compare with Firefox")
class TestFirefoxComparison(unittest.TestCase):
    """cert-info's chains against Firefox's for the top Tranco domains."""

    @classmethod
    def setUpClass(cls):
        cls.report = run_comparison(tranco_domains(TRANCO_LIST, TOP))
        with open(REPORT, "w", encoding="utf-8") as out:
            json.dump(cls.report, out, indent=2)
        print(f"\nReport: {os.path.abspath(REPORT)}\n"
              f"Summary: {json.dumps(cls.report['summary'], indent=2)}", file=sys.stderr)

    def test_intermediates_were_preloaded(self):
        sync = self.report["intermediates_sync"]
        self.assertGreater(sync.get("imported", 0), 1000, sync)

    def test_path_building_matches_firefox(self):
        """Same certificates in, same chain out."""
        for r in self.report["results"]:
            if r["firefox_status"] == "built":
                with self.subTest(domain=r["domain"]):
                    self.assertTrue(r["path_building"]["matches"], _mismatch(r, "path_building"))

    def test_untrusted_chains_are_rejected(self):
        """When Firefox finds no trusted chain, Firefox's rules must not find one either."""
        for r in self.report["results"]:
            if r["firefox_status"] == "rejected" and r["firefox_error"] == "untrusted":
                with self.subTest(domain=r["domain"]):
                    self.assertFalse(r["path_building"]["strict"], _mismatch(r, "path_building"))

    def test_end_to_end_matches_firefox(self):
        """When both connections received the same leaf, the chains must be equal."""
        for r in self.report["results"]:
            if r["firefox_status"] == "built" and r["end_to_end"]["same_leaf"]:
                with self.subTest(domain=r["domain"]):
                    self.assertTrue(r["end_to_end"]["matches"], _mismatch(r, "end_to_end"))


def _mismatch(result: dict, kind: str) -> str:
    """Readable description of a mismatch."""
    firefox = [c["subject"] for c in result["firefox_chain"]]
    ours = [c["subject"] for c in result[kind]["chain"]]
    return f"\n  Firefox:   {firefox}\n  cert-info: {ours}"


if __name__ == "__main__":
    unittest.main()
