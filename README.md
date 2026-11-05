# DISSECT: Certificate Analysis

The **Certificate Analysis** component (`cert-info`) is part of the **DISSECT** project. It retrieves the TLS certificate chain of a domain, builds it the same way Firefox does, and validates it with Firefox's rules: expiry, hostname, signatures, CA rights, supported algorithms, revocation, Certificate Transparency and key pins. It also reports the strength of the cryptographic algorithms used according to NIST.

## Overview

For each domain, `cert-info`:

- **Retrieves what the server sends**: its certificates, its stapled OCSP response and its Signed Certificate Timestamps (SCTs), using a TLS handshake that offers what Firefox offers: TLS 1.2 and 1.3, its cipher suites, signature algorithms and key exchange groups, including the post-quantum hybrid `X25519MLKEM768` with key shares for it, X25519 and P-256 (this needs OpenSSL 3.5 or later, as in the Docker image; older versions offer the classical groups only). Servers with several certificates (e.g. RSA and ECDSA) then send the one Firefox would receive. If that handshake fails, OpenSSL's defaults are tried, then legacy settings for old servers, which offer only classical key exchange groups: some old servers and middleboxes break on the larger ClientHello of a post-quantum key share. Firefox cannot connect to those, but `cert-info` still retrieves their certificates.
- **Builds the chain like Firefox**, using the Mozilla root store and Firefox's preloaded intermediate certificates (see [How the chain is built](#how-the-chain-is-built)).
- **Validates the chain with Firefox's rules** (see [When is a chain valid?](#when-is-a-chain-valid)):
  - **Chain of trust**: each certificate is signed by the next one, and the chain ends at a root of the Mozilla trust store.
  - **Validity period**: expired or not-yet-valid certificates.
  - **Hostname**: the leaf certificate's Subject Alternative Name matches the domain.
  - **CA rights**: issuers have Basic Constraints with `cA` set and may issue TLS server certificates.
  - **Algorithms**: keys and signature algorithms Firefox supports.
  - **Revocation**: OneCRL, CRL, stapled OCSP and OCSP, as Firefox uses them; OCSP Must-Staple.
  - **Certificate Transparency** and Firefox's **key pins**.
  - **Algorithm strength**: the NIST SP 800-131A and SP 800-186 status of the signature hash, public key and elliptic curve, for information (see [Algorithm strength](#algorithm-strength-nist)).
  - **DNSSEC**: whether the domain's DNS answer is DNSSEC-validated.

## How the chain is built

Servers often send chains that differ from the one a browser shows: certificates in the wrong order, missing intermediates, extra certificates, or cross-signed copies of roots meant for old clients. `cert-info` ignores how the server arranged its certificates and builds the chain the way Firefox (mozilla::pkix) does:

1. The certificates sent by the server form an unordered pool. The first one is the leaf.
2. An issuer is a certificate whose subject is exactly the child's issuer name and whose key verifies the child's signature.
3. Candidate issuers are tried in this order: roots of the Mozilla trust store, certificates sent by the server, then Firefox's preloaded intermediates (all intermediates disclosed to [CCADB](https://www.ccadb.org/)).
4. Building stops at the first trusted root. When the server sends a cross-signed copy of a trusted root, the self-signed root from the trust store is used instead, exactly as in Firefox. A cross-signed certificate is only kept when its self-signed version is not in the Mozilla store (e.g. Let's Encrypt `Root YR`, signed by `ISRG Root X1`).
5. Every candidate issuer, **the root included**, must pass Firefox's checks: validity period, Basic Constraints `cA`, Key Usage `keyCertSign` (if present), Extended Key Usage `serverAuth` (if present; `anyExtendedKeyUsage` does not count), path length, no critical extension Firefox does not understand, and a supported key (RSA of at least 1024 bits, or ECDSA on P-256, P-384 or P-521). Intermediates must also be signed with RSA or ECDSA and SHA-256, SHA-384 or SHA-512 (no SHA-1). A root's own self-signature is never checked, since trust comes from the trust store. An unsuitable candidate is skipped and the next one is tried, so an expired root can be bypassed through a cross-signed copy.
6. Certificates on **OneCRL**, Mozilla's list of revoked CA certificates, are never used.
7. **Name constraints**: a CA whose Name Constraints extension (or the constraints NSS imposes on a few roots, e.g. TUBITAK's root is limited to `.tr`) does not allow the names of the certificates below it is not used for them. The rules are mozilla::pkix's: every Subject Alternative Name is checked against the subtrees of its type (DNS names, IP addresses, email addresses); the subject is checked as a directory name, attribute by attribute on its encoding (PrintableString and UTF8String count as the same); without a Subject Alternative Name extension, the subject's email addresses are checked too, and for a server certificate without DNS names or IP addresses, its last Common Name. Excluded directory names are not supported by Firefox and reject every certificate below, and a URI or other unsupported name is rejected if the constraints have a subtree of its type. Unlike RFC 5280, constraints also apply to self-issued CA certificates.
8. **OCSP Must-Staple** (TLS Feature extension): a certificate must repeat its issuer's TLS Feature extension.
9. **Distrust dates**: when Mozilla phases out a root, it can stop trusting it only for certificates issued after a date. A chain ending at such a root is rejected if the leaf was issued after that date.
10. **Key pins**: for a few hosts (Mozilla and Google services, among others), Firefox requires the chain to contain one of a set of keys. A chain to a Mozilla root without any of them is rejected.
11. **RSA key sizes**: Firefox first requires 2048-bit RSA keys in every certificate, then accepts 1024 bits, so a chain with only 2048-bit keys is preferred.
12. **Search limit**: like Firefox, the search gives up after examining 200,000 candidate issuers (counted after the loop, name constraint and Must-Staple checks), which only matters for servers sending large tangles of same-named certificates.

In each case Firefox then tries other paths, and so does `cert-info`. Problems of the leaf itself (expiry, OneCRL, an unsupported key, ...) do not change the path: Firefox reports them after building it, and so does `cert-info`.

13. **Extended Validation first.** For each EV policy in the leaf certificate, in the leaf's order, Firefox first tries to build an EV chain: every certificate must assert that policy (intermediates may assert `anyPolicy`), and the chain must end at a root that Firefox's EV list registers for that policy, with 2048-bit RSA keys. Other roots are not trusted in that attempt. Only if no EV chain exists is the ordinary chain built. This is why some EV chains go through a cross-signed root: e.g. for a leaf whose first policy is Sectigo's own EV policy, `Sectigo Public Server Authentication Root E46` (registered only for the CA/Browser Forum EV policy) is not trusted, so the chain continues through the cross-signed E46 to `USERTrust ECC Certification Authority`.

When Firefox would reject every possible chain (e.g. because of an expired intermediate or a SHA-1 signature), `cert-info` searches again without those checks so that it can still report on the chain. The chain is then invalid, with the note `Firefox would not accept this chain.`, and the problems appear as issues on the certificates concerned.

Firefox does not download missing issuers through the Authority Information Access (AIA) extension. `cert-info` only does so when no trusted chain can be built, so it can still report on the chain; such certificates have the origin `AIA`, and the chain is invalid because Firefox would not accept it. When no trusted chain exists at all, the most complete chain found is returned and marked as invalid.

The trust data comes from the current Firefox release and lives in seven files, used identically in every environment:

| File | Contents | Source |
|---|---|---|
| `src/trust/data/mozilla-certs.pem` | Mozilla root store: roots Firefox trusts for websites | Firefox source, `security/nss/lib/ckfw/builtins/certdata.txt` |
| `src/trust/data/mozilla-distrust.csv` | Roots' distrust dates for websites | Same `certdata.txt` (`CKA_NSS_SERVER_DISTRUST_AFTER`) |
| `src/trust/data/mozilla-intermediates.pem` | Firefox's preloaded intermediates | Firefox Remote Settings, `security-state/intermediates` |
| `src/trust/data/firefox-ev-roots.csv` | Roots Firefox trusts for each EV policy | Firefox source, `security/certverifier/ExtendedValidation.cpp` |
| `src/trust/data/mozilla-onecrl.json` | OneCRL: revoked CA certificates | Firefox Remote Settings, `security-state/onecrl` |
| `src/trust/data/firefox-ct-logs.json` | Certificate Transparency logs Firefox knows, and when the list expires | Firefox source, `security/ct/CTKnownLogs.h` |
| `src/trust/data/firefox-pins.json` | Firefox's static key pins, and when they expire | Firefox source, `security/manager/ssl/StaticHPKPins.h` |

## When is a chain valid?

The response's `status` is `valid` only if all of the following hold. The rules are Firefox's (mozilla::pkix and its certificate verifier):

- **Trust**: the chain ends at a root of the Mozilla trust store, and Firefox would build the same chain: it passes the checks of [How the chain is built](#how-the-chain-is-built) and needs no AIA download. Certificates on OneCRL, certificates breaking a name constraint and roots past their distrust date get an issue saying so; a chain without any of the host's pinned keys gets the note `Chain contains none of the keys Firefox pins for this host.`
- **Every certificate** is valid:
  - Firefox can process its extensions: none is malformed or duplicated, and every critical extension is one Firefox understands;
  - its signature verifies with the next certificate's key (a root's with its own);
  - it is within its validity period;
  - its issuer is a CA (Basic Constraints `cA`; version 1 roots are accepted without it) allowed to sign certificates (Key Usage `keyCertSign`, if present) for TLS servers (Extended Key Usage `serverAuth`, if present), within its path length constraint;
  - its key is supported: RSA of at least 1024 bits, or ECDSA on P-256, P-384 or P-521 (not Ed25519, DSA or other curves);
  - except for roots, its signature uses RSA PKCS#1 v1.5 or ECDSA with SHA-256, SHA-384 or SHA-512 (not SHA-1, MD5 or SHA-224), or RSA-PSS with one of the three standard parameter sets (MGF-1 with the same hash and a salt as long as the hash); the algorithm written in the signed part of the certificate must be the same as the one outside it.
- **The leaf** may be used by the server:
  - it matches the domain: only the Subject Alternative Name is used, never the Common Name. DNS names are matched case-insensitively; a wildcard must be the whole first label and needs two labels after it (`*.example.com`, not `*.com`) and matches exactly one label (`www.example.com`, not `a.b.example.com`). Names are tried in order, and an invalid DNS name stops the search, as in Firefox. An IP address only matches an IP address entry;
  - its Extended Key Usage (if present) includes `serverAuth` and not `OCSPSigning`, and its Key Usage (if present) allows `digitalSignature`, `keyEncipherment` or `keyAgreement`; it is not a CA certificate;
  - it is not revoked (see below), and if it has the OCSP Must-Staple extension, the server stapled an OCSP response;
  - it meets Firefox's **Certificate Transparency** policy (see below).

The NIST status of the algorithms is reported as issues (e.g. `Key no longer allowed for applying cryptographic protection` for a 1024-bit RSA key) but does not make a certificate invalid; see [Algorithm strength](#algorithm-strength-nist).

### Revocation

Firefox checks CA certificates only against OneCRL. For the leaf, `cert-info` follows Firefox's order:

1. **CRLite**: Firefox's compressed set of all revocations, built from the CAs' CRLs. When it covers the certificate, its answer is final. `cert-info` cannot read Firefox's CRLite filters and uses their source instead, the certificate's CRL. A verified CRL that lists the certificate makes it revoked. A CRL that does not list it is final only if it is current and complete: not expired, not a delta CRL, not an indirect CRL, and not limited to CA certificates or to some revocation reasons. Otherwise the next steps decide.
2. **The stapled OCSP response**, if the server sent one: `good` accepts the certificate and `revoked` rejects it. An expired response (whatever it says), a responder answering `tryLater`, a response signed by a certificate the issuer did not authorise, or a response about another certificate is ignored (with a warning); any other problem (bad signature, `unknown` status, malformed response, response dated in the future) makes the certificate invalid.
3. Certificates valid for less than 10 days are not checked further.
4. Firefox does not fetch OCSP for certificates under a Mozilla root, because it relies on CRLite. When no CRL could be used, `cert-info` asks the OCSP responder instead, as a stand-in for CRLite; only a `revoked` answer counts.

Expired certificates are not checked for revocation. A certificate without CRL or OCSP information only gets a warning. CRLs and OCSP responses are only used if their signature verifies with the issuer's key (or, for OCSP, with an end-entity certificate the issuer authorised for OCSP signing, which must also pass Firefox's checks: supported extensions, key and signature algorithm, validity period, not on OneCRL). OCSP requests identify the certificate with SHA-1, as Firefox does; some responders (e.g. DigiCert, Microsoft, Amazon) reject SHA-256. A CRL or OCSP responder that cannot be reached gives a warning, not an issue (soft fail, as in browsers). Downloaded CRLs and successful OCSP responses are kept in memory and reused until their next update, but for at most one hour (environment variable `CERTINFO_REVOCATION_CACHE_SECONDS`, `0` disables the cache), so a revocation published before a CRL's next update is seen within that delay. Failed downloads and expired CRLs are never reused; signatures and dates are checked again on every use. URLs taken from certificates (CRL, OCSP, AIA) are only fetched over `http://`, from public IP addresses, without following redirects, so that analysing a malicious server cannot make the service reach internal systems.

### Certificate Transparency

For a chain to a Mozilla root, Firefox requires proof that the leaf was published in Certificate Transparency logs: Signed Certificate Timestamps (SCTs), embedded in the certificate, sent in the TLS handshake or included in the stapled OCSP response. An SCT counts if it comes from a log Firefox knows, its signature verifies, and it is not dated in the future or after the root's distrust date. The policy is met by either:

- two SCTs delivered in the handshake or the stapled OCSP response, from two different logs run by two different operators (as in Firefox, the OCSP response's SCTs only count when the revocation check used that response, not when the CRL settled it); or
- embedded SCTs from at least 2 different logs (3 if the certificate is valid for more than 180 days) and 2 different operators, at least one of them still admissible (SCTs from a retired log count if it was retired after the certificate was issued).

SCTs from tiled (static-ct-api) logs must carry the certificate's index in the log. Firefox stops enforcing CT when its log list expires (the expiration date is in `firefox-ct-logs.json`); after that, the note `Certificate Transparency was not checked: ...` is added. A leaf that fails the policy gets the issue `Certificate does not meet Firefox's Certificate Transparency requirements`, with the SCT counts as a warning. CT is not checked for a leaf outside its validity period, which is already invalid.

### Differences from Firefox

- **CRLite** is approximated with the CRL and OCSP responder of the certificate (see [Revocation](#revocation)), so a revocation published after the analysis, or an unreachable CRL, can make results differ for a short time.
- Firefox reports the first problem it finds; `cert-info` reports all of them.
- Certificates and settings added by the user (e.g. enterprise roots, certificate exceptions) are not considered.

## Installation

`cert-info` runs as a web service inside a Docker container, so Docker is required.

### Using the deployment script

```bash
./deploy.sh
```

The script builds the image, replaces any existing `cert-info` container, waits until it is healthy, and prints a summary. It can be configured with environment variables:

| Variable | Default | Description |
|---|---|---|
| `TAG` | `latest` | Image tag |
| `CONTAINER_NAME` | `cert-info` | Container name |
| `HOST_PORT` | `6010` | Port published on the host |
| `PORT` | `6010` | Port the API listens on inside the container |
| `WORKERS` | `4` | Number of uvicorn worker processes |
| `REFRESH_TRUST_DATA` | `true` | Download the current Mozilla trust data (roots and distrust dates, preloaded intermediates, EV roots, OneCRL, CT logs, key pins) during the build (`false` uses the bundled files) |

Example:

```bash
HOST_PORT=8080 WORKERS=2 ./deploy.sh
```

### Manually

```bash
# Build with the bundled trust data
docker build -t cert-info:latest .

# Or refresh the trust data from Mozilla during the build
# (any new value re-runs the download step)
docker build --build-arg REFRESH_TRUST_DATA=$(date -u +%Y-%m-%d) -t cert-info:latest .

docker run -d -p 6010:6010 --name cert-info cert-info:latest
```

The container runs as an unprivileged user and reports its health through the `/health` endpoint.

## Usage

Send a `GET` request to `/certinfo/{domain}`. The domain may include a scheme and a port; the default port is 443.

| Query parameter | Default | Description |
|---|---|---|
| `showcert` | `false` | Include the decoded fields of every certificate (`certificate` object) |
| `force` | `false` | Analyse the domain even if the TCP check or the HTTPS probe fails |

Examples:

```bash
curl 'http://localhost:6010/certinfo/www.uminho.pt?showcert=true'
curl 'http://localhost:6010/certinfo/example.com:8443'
```

Other endpoints:

- `GET /health`: returns `{"status": "ok"}` when the service is running.
- `GET /docs`: interactive API documentation.

If the analysis cannot be performed, the response is an error object:

```json
{"status": "error", "error": "Domain is not reachable."}
```

Possible errors: `Invalid domain.`, `Invalid port number.`, `Domain is not reachable.`, `Domain does not support HTTPS.`, `Failed to retrieve certificate chain.`

## Output

Example response for `GET /certinfo/www.uminho.pt?showcert=true` (signatures shortened):

```json
{
    "domain": "www.uminho.pt",
    "date": "2026-11-05 10:22:32",
    "ip-address": "193.137.9.217",
    "redirect": false,
    "original": "www.uminho.pt",
    "status": "valid",
    "analysis": [],
    "chain": [
        {
            "id": "Leaf Certificate",
            "origin": "Server",
            "status": "valid",
            "issues": [],
            "warnings": [
                "Certificate uses wildcard domain"
            ],
            "certificate": {
                "subject": "CN=*.uminho.pt,O=Universidade do Minho,L=Braga,C=PT",
                "issuer": "CN=GEANT TLS RSA 1,O=Hellenic Academic and Research Institutions CA,C=GR",
                "serial_number": "6b63f66ad3cd773743429428aac2695d",
                "valid_from": "2025-12-11 10:28:57",
                "valid_until": "2026-12-11 10:28:57",
                "signature_algorithm": "sha256WithRSAEncryption",
                "public_key_type": "RSAPublicKey",
                "public_key_size": 4096,
                "type": "Leaf Certificate",
                "SAN": [
                    "*.uminho.pt",
                    "uminho.pt"
                ],
                "key_usage": {
                    "digital_signature": true,
                    "key_encipherment": true,
                    "data_encipherment": false,
                    "key_cert_sign": false,
                    "crl_sign": false
                },
                "extended_key_usage": [
                    "clientAuth",
                    "serverAuth"
                ],
                "crl_distribution_points": [
                    "http://crl.harica.gr/HARICA-GEANT-TLS-R1.crl"
                ],
                "ocsp_urls": [
                    "http://ocsp-tls.harica.gr"
                ],
                "ca_issuers_urls": [
                    "http://crt.harica.gr/HARICA-GEANT-TLS-R1.cer"
                ],
                "validation_level": "Organization Validation (OV)",
                "fingerprint_SHA256": "04c0566d8e985e4cd81b3360f34397e8755309e4dc3677c56b74ea9c8d1e07a5",
                "signature": "0134a0bfe8c24259..."
            }
        },
        {
            "id": "Intermediate Certificate",
            "origin": "Server",
            "status": "valid",
            "issues": [],
            "warnings": [],
            "certificate": {
                "subject": "CN=GEANT TLS RSA 1,O=Hellenic Academic and Research Institutions CA,C=GR",
                "issuer": "CN=HARICA TLS RSA Root CA 2021,O=Hellenic Academic and Research Institutions CA,C=GR",
                "...": "..."
            }
        },
        {
            "id": "Root CA Certificate",
            "origin": "Mozilla CA Bundle",
            "status": "valid",
            "issues": [],
            "warnings": [],
            "certificate": {
                "subject": "CN=HARICA TLS RSA Root CA 2021,O=Hellenic Academic and Research Institutions CA,C=GR",
                "issuer": "CN=HARICA TLS RSA Root CA 2021,O=Hellenic Academic and Research Institutions CA,C=GR",
                "...": "..."
            }
        }
    ]
}
```

### Response fields

| Field | Description |
|---|---|
| `domain` | Domain whose chain was analysed (after following HTTPS redirects) |
| `date` | Time of the analysis (UTC) |
| `ip-address` | IPv4 address of `domain` (its IPv6 address if it has no IPv4 address; `null` if it does not resolve) |
| `redirect` | `true` if the requested domain redirected to another one |
| `original` | The requested domain |
| `status` | `valid` or `invalid` (see [When is a chain valid?](#when-is-a-chain-valid)) |
| `analysis` | Notes about the chain as a whole (see below) |
| `chain` | The chain, from the leaf to the root |

Possible `analysis` notes:

| Note | Meaning |
|---|---|
| `Extra certificates were provided.` | The server sent duplicate certificates, or certificates unrelated to the chain. Cross-signed copies of the chain's root are not counted. |
| `Missing certificates had to be fetched from AIA.` | No trusted chain could be built from the server's certificates and Firefox's intermediates; issuers were downloaded through AIA. |
| `Chain does not lead to a root in the Mozilla trust store.` | No trusted chain exists. |
| `Firefox would not accept this chain.` | The chain reaches a trusted root, but only by ignoring checks Firefox makes (see the issues), or only with certificates downloaded through AIA. |
| `Chain contains none of the keys Firefox pins for this host.` | The host has static key pins in Firefox and the chain contains none of the pinned keys. |
| `Certificate Transparency was not checked: the CT log list has expired or is missing.` | The bundled CT log list has expired, so Firefox would not enforce CT either; update the trust data. |

### Chain entries

| Field | Description |
|---|---|
| `id` | `Leaf Certificate`, `Intermediate Certificate` or `Root CA Certificate` |
| `origin` | Where the certificate came from: `Server`, `Mozilla CA Bundle` (trust store root), `Mozilla Intermediate Preload` (Firefox's preloaded intermediates) or `AIA` |
| `status` | `valid` or `invalid` |
| `issues` | Problems found. All make the certificate invalid, except the NIST algorithm findings (see [Algorithm strength](#algorithm-strength-nist)). |
| `warnings` | Informational findings (wildcard usage, missing Common Name, DNSSEC, missing revocation information, CRLs or OCSP responses that could not be used or were ignored, the SCT counts when Certificate Transparency fails, certificate fetched through AIA) |
| `certificate` | Decoded certificate fields; only present with `showcert=true` |

### Certificate fields

| Field | Description |
|---|---|
| `subject`, `issuer` | Distinguished names (RFC 4514) |
| `serial_number` | Serial number, hexadecimal |
| `valid_from`, `valid_until` | Validity period (UTC) |
| `signature_algorithm` | Signature algorithm |
| `public_key_type`, `public_key_size` | Public key type and size in bits |
| `type` | `Leaf Certificate`, `Intermediate Certificate` or `Root CA` (based on the certificate's own fields) |
| `SAN` | Subject Alternative Names (if present) |
| `key_usage`, `extended_key_usage` | Key Usage flags and Extended Key Usages (if present) |
| `crl_distribution_points`, `ocsp_urls`, `ca_issuers_urls` | Revocation and issuer URLs (if present) |
| `validation_level` | `Extended Validation (EV)`, `Organization Validation (OV)` or `Domain Validation (DV)`, from the CA/Browser Forum policy OIDs; without them, OV if the subject has an Organization, DV otherwise. On CA certificates it is the level the CA issues. |
| `fingerprint_SHA256` | SHA-256 of the certificate, hexadecimal |
| `signature` | The certificate's signature, hexadecimal |

## Algorithm strength (NIST)

The hash used in each certificate's signature and each certificate's public key are classified according to [NIST SP 800-131A](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final) (Rev. 2, and the Rev. 3 initial public draft) and [NIST SP 800-186](https://csrc.nist.gov/pubs/sp/800/186/final). The rules are kept in CSV files in `src/validation/nist/` (the NIST documents themselves are in `docs/nist/`):

| File | Contents |
|---|---|
| `hash_functions.csv` | Status of each hash function (MD5, SHA-1, SHA-2, SHA-3) |
| `algorithms_key_lengths.csv` | Status of RSA, DSA, ECDSA and EdDSA keys by key size |
| `curves.csv` | Status of each elliptic curve, with the SP 800-186 section it comes from |

Statuses and the issue reported for each:

| Status | Issue text (prefixed with `Hash ` or `Key `) |
|---|---|
| Acceptable | none |
| Deprecated | `may be used, but user must accept security risks` |
| Legacy | `may be used only to process already protected information` |
| Disallowed | `no longer allowed for applying cryptographic protection` |

These findings are reported for information and do not make a certificate invalid: whether Firefox accepts an algorithm is decided by its own rules (see [When is a chain valid?](#when-is-a-chain-valid)). For example, a 1024-bit RSA key is `Disallowed` for NIST but accepted by Firefox, while SHA-1 signatures are `Disallowed` for NIST and rejected by Firefox (`Signed with SHA-1, which Firefox rejects`).

- **Hash**: the hash of the certificate's signature, e.g. `Hash no longer allowed for applying cryptographic protection` for SHA-1. It is not checked for roots, whose self-signature is not relied upon. EdDSA signatures have the hash built into the algorithm and are always acceptable.
- **Key**: the key's algorithm and size, e.g. RSA below 2048 bits or DSA are disallowed. For elliptic-curve keys (ECDSA and EdDSA), the curve's status is also taken into account and the worse of the two is reported; when the curve is not acceptable, an extra issue names it, e.g. `Usage of curve sect233k1 is Deprecated`.
- **Curves**: P-224 to P-521, Edwards25519, Edwards448 and the Brainpool curves (allowed by SP 800-186 for interoperability) are acceptable; binary curves of 233 bits and more are deprecated; P-192, K-163 and B-163 are legacy-use only; secp256k1 is disallowed (SP 800-186 only allows it for blockchain applications).
- Hash functions, key types or curves that are not in the tables are reported as `Could not determine signature hash algorithm.` or `Could not determine public key algorithm`.

## Updating the trust data

Mozilla updates the preloaded intermediates and OneCRL daily, and the root store, EV list, CT logs and key pins with each Firefox release. The CT log list and the key pins have an expiration date (a few months after the Firefox release they come from); like Firefox, `cert-info` stops enforcing them once it has passed, so the data should be refreshed regularly. The deployment script downloads the current data on every build. To update the bundled files in the repository:

```bash
python scripts/update_trust_data.py
```

This runs the six update scripts, which can also be run on their own:

| Script | Updates |
|---|---|
| `scripts/update_mozilla_roots.py` | `mozilla-certs.pem` and `mozilla-distrust.csv`, from `certdata.txt` of the Firefox release |
| `scripts/update_mozilla_intermediates.py` | `mozilla-intermediates.pem`; every certificate is checked against the SHA-256 published by Mozilla |
| `scripts/update_firefox_ev_roots.py` | `firefox-ev-roots.csv`, from `ExtendedValidation.cpp` of the Firefox release |
| `scripts/update_mozilla_onecrl.py` | `mozilla-onecrl.json` |
| `scripts/update_firefox_ct_logs.py` | `firefox-ct-logs.json`, from `CTKnownLogs.h` of the Firefox release |
| `scripts/update_firefox_pins.py` | `firefox-pins.json`, from `StaticHPKPins.h` of the Firefox release |

A file whose download fails keeps its previous version. The root store and the EV list come from the same Firefox release, so they stay in step.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn src.api:app --reload --port 6010
```

The `openssl` and `dig` command-line tools must be installed.

### Repository structure

```
src/
  api.py                      HTTP API (FastAPI app: src.api:app)
  certificate_info.py         Entry point: CertificateInformation.analyze(domain)
  fetch/                      Talking to the analysed server
    domain.py                   Domain and port parsing and checks
    https_probe.py              HTTPS probe, following redirects
    tls.py                      What the server sends in the TLS handshake: certificates, stapled
                                OCSP response, SCTs (openssl, Firefox-like ClientHello)
    empty-ct-logs.cnf           Empty CT log list for openssl (SCTs are verified by cert-info)
    network.py                  Fetching URLs from certificates (CRL, OCSP, AIA) safely
    cache.py                    In-memory cache for downloaded CRLs and OCSP responses
  trust/                      Mozilla trust data
    store.py                    Loading the data files (TrustStore)
    data/                       Roots, distrust dates, preloaded intermediates, EV roots, OneCRL,
                                CT logs, key pins
  chain/                      Building the chain the way Firefox does
    path_builder.py             Path building (PathBuilder)
    certificate_rules.py        Firefox's checks on each certificate (extensions, algorithms, CA rights)
    pinning.py                  Firefox's static key pins
    signatures.py               Signature verification
    name_constraints.py         Name constraints
    names.py                    DNS names and email addresses as Firefox validates and compares them
    der.py                      Reading encoded (DER) structures
    aia.py                      Downloading a missing issuer through AIA
  validation/                 Judging the chain and its certificates
    chain_validator.py          Chain-level rules and the API response (ChainValidator)
    certificate_validator.py    Checks on each certificate (CertificateValidator)
    revocation.py               Leaf revocation (CRL, stapled OCSP, OCSP) and OCSP Must-Staple
    transparency.py             Certificate Transparency (SCTs and Firefox's CT policy)
    certificate_fields.py       Certificate fields in the response (showcert)
    nist/                       NIST algorithm tables and their parser
scripts/                      Updating the trust data
tests/                        Unit tests, and the opt-in comparison with Firefox
docs/nist/                    The NIST publications the algorithm tables come from
```

### Comparing with Firefox

`tests/test_firefox_comparison.py` checks that `cert-info` builds the same chains as Firefox for the top domains of a [Tranco](https://tranco-list.eu) list. It starts a headless Firefox (with its preloaded intermediates enabled) and, from Firefox's privileged context, requests `https://<domain>/` for many domains at a time, following redirects but stopping at the response headers. For each connection it reads, from Firefox's own security information, the certificates the server sent and the chain Firefox built. It then checks that:

- given exactly the certificates Firefox received, `cert-info` builds exactly Firefox's chain, and finds no chain Firefox would accept when Firefox rejects the chain as untrusted;
- end to end (`cert-info` fetching the certificates itself), the chains are equal whenever both connections received the same leaf certificate.

It needs Firefox, network access and Selenium, takes about one minute for 250 domains, and only runs when enabled:

```bash
pip install -r requirements-dev.txt
CERTINFO_FIREFOX_TEST=1 python -m unittest tests.test_firefox_comparison -v
```

Options (environment variables): `CERTINFO_TRANCO_LIST` (list ID, default `JZPGY`), `CERTINFO_TRANCO_TOP` (default `250`), `CERTINFO_FIREFOX_BINARY` (path to Firefox), `CERTINFO_FIREFOX_CONCURRENCY` (requests Firefox makes at the same time, default `24`) and `CERTINFO_FIREFOX_REPORT` (JSON report with every domain's chains, default `firefox_comparison.json`).

## Contributing

Contributions are more than welcome and they are what makes the community great! Feel free to open issues, suggest features, or submit pull requests. However, in order to maintain some order, the following set of conventions should be used:

- **Branches**: To contribute, please create a new branch locally using the structure `tag/name`, where `tag` consists of a descriptive tag of the contribution, and `name` consists in the name of the branch. Do not commit directly to the `main` branch. Some of the possible tags include:
    - **new**: new functionalities
    - **docs**: documentation
    - **enhancement**: enhancing some part of the code
    - **refactor**: major changes in the code, namely in the code structure
    - **bugfix**: fixing some bug in the code

- **Commits**: When adding commits to your branch, use descriptive commit messages, following the format:
    ```bash
    git commit -m "tag: brief commit description
    
    Here you can place a more detailed description of what is included in
    the commit, making sure to not exceed 72 characters per line. The tag 
    used above should be the same as the one used in the branch, and the
    brief commit description should be self-explanatory."
    ```

- **Testing**: To test the code, execute the `python -m unittest` command in the root of the repository. Make sure all tests pass successfully. The tests in `tests/test_analysis.py` and `tests/test_domain.py` need network access; the others run offline, except the Firefox comparison, which is skipped unless enabled (see [Comparing with Firefox](#comparing-with-firefox)). To test using `pylint`, run `pylint src` at the root of the project and make sure the score is above `9.0`; `python -m pyflakes src scripts tests` (from `requirements-dev.txt`) must report nothing.

- **Pull Requests**: When opening a pull request, make sure to assign at least a reviewer so that all the code being merged has been validated by more than one person. When merging the pull request, make sure to **squash** all **commits** **before merging**.

## Authors

- [Diogo Ribeiro](https://github.com/ribeiropdiogo)
- [João Marco Silva](https://github.com/jotamarco)

## License

cert-info is licensed using [GNU v3](/LICENSE)
