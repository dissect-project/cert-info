# Tests

The tests use Python's built-in `unittest`. Most of them run offline: they generate their own certificates, CRLs, OCSP responses and CT logs, and mock the network, DNS and `dig`. A few use the network (marked below), and the comparison with Firefox only runs when explicitly enabled.

## Running the tests

Run every command from the root of the repository (the folder that contains `src/`), with the virtual environment active:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt     # requirements.txt + Selenium + pyflakes
```

| What | Command |
|---|---|
| All tests (the Firefox comparison is skipped) | `python -m unittest` |
| One file | `python -m unittest tests.test_path_builder` |
| One class | `python -m unittest tests.test_path_builder.TestKeyPins` |
| One test | `python -m unittest tests.test_path_builder.TestKeyPins.test_host_lookup` |
| Verbose (one line per test) | add `-v`, e.g. `python -m unittest -v` |
| Comparison with Firefox | `CERTINFO_FIREFOX_TEST=1 python -m unittest tests.test_firefox_comparison -v` |
| Static check (must report nothing) | `python -m pyflakes src scripts tests` |

The whole suite takes a few seconds. `test_analysis.py` and `test_domain.py` need network access and can be slow or fail if the network or DNS is unavailable; all other files (except the Firefox comparison) run offline.

## Test files

| File | What it tests | Network |
|---|---|---|
| [`test_analysis.py`](#test_analysispy) | A full analysis of a real domain | Yes |
| [`test_domain.py`](#test_domainpy) | Domain validation, reachability, host and port parsing | Yes (reachability) |
| [`test_path_builder.py`](#test_path_builderpy) | Building the chain the way Firefox does | No |
| [`test_trust_data.py`](#test_trust_datapy) | Mozilla trust data: root store, distrust dates, OneCRL, name constraints, update scripts | No |
| [`test_validation_rules.py`](#test_validation_rulespy) | Validity rules: issuer rights, hostname, algorithms, extensions, revocation, Must-Staple, DNSSEC | No |
| [`test_transparency.py`](#test_transparencypy) | Certificate Transparency, reading the TLS handshake, Firefox-like ClientHello | No |
| [`test_signatures.py`](#test_signaturespy) | Signature verification | No |
| [`test_nist_parser.py`](#test_nist_parserpy) | NIST classification of hashes, keys and curves | No |
| [`test_certificate_fields.py`](#test_certificate_fieldspy) | Validation level (EV/OV/DV) in the response | No |
| [`test_client.py`](#test_clientpy) | User-Agent, header-only HTTPS probe, back-off after 429/503 | No |
| [`test_firefox_comparison.py`](#test_firefox_comparisonpy) | cert-info's chains against Firefox's, on the Tranco top domains | Yes, opt-in |

---

### `test_analysis.py`

End-to-end check of `CertificateInformation.analyze` on a real domain.

| Test | Checks that |
|---|---|
| `TestDomainAnalysis.test_domains` | Analysing `cm-porto.pt` returns a `valid` or `invalid` status and a chain starting with the leaf certificate |

### `test_domain.py`

Domain checks in `src/fetch/domain.py` and `src/fetch/https_probe.py`.

| Test | Checks that |
|---|---|
| `TestDomainValidation.test_valid_domains` | Ordinary domains, with or without `https://`, are accepted |
| `TestDomainValidation.test_valid_uncommon_domains` | Long and internationalised TLDs, `xn--` labels, underscores and explicit ports are accepted |
| `TestDomainValidation.test_invalid_domains` | Malformed domains (one-letter TLD, no TLD, bad scheme) are rejected |
| `TestDomainValidation.test_reachable_domains` | A live domain is reachable (network) |
| `TestDomainValidation.test_unreachable_domains` | Non-existent domains are unreachable (network) |
| `TestHostAndPort.testsplit_host_port` | Host and port are split correctly, invalid ports are detected |
| `TestHostAndPort.test_host_port_from_redirect` | The host and TLS port are taken correctly from a redirect URL |

### `test_path_builder.py`

Path building (`src/chain/path_builder.py`) on a generated PKI, so the tests run offline and do not depend on dates.

**`TestPathBuilder`**: basic Firefox path building

| Test | Checks that |
|---|---|
| `test_stops_at_trusted_root_instead_of_cross_sign` | The trusted root is used instead of a cross-signed copy sent by the server, which is not counted as extra |
| `test_unrelated_certificate_is_extra` | A certificate unrelated to the chain is reported as extra |
| `test_uses_cross_sign_when_only_old_root_is_trusted` | The chain goes through the cross-sign when only the old root is trusted |
| `test_server_order_does_not_matter` | The order in which the server sends its certificates does not change the chain |
| `test_missing_intermediate_comes_from_preload` | A missing intermediate is taken from Firefox's preloaded intermediates |
| `test_server_copy_of_root_is_not_extra_when_used` | A root sent by the server and used in the chain is not extra |
| `test_duplicates_are_extra` | Duplicate certificates are reported as extra |
| `test_expired_intermediate_is_skipped_for_valid_one` | An expired intermediate is skipped when a valid one exists |
| `test_expired_intermediate_is_kept_when_no_alternative` | An expired intermediate is reported when there is no alternative |
| `test_leaf_cannot_act_as_issuer` | A non-CA certificate is never used as an issuer |
| `test_untrusted_self_signed_root` | A chain ending at an unknown self-signed root is untrusted |
| `test_incomplete_chain` | A chain missing its issuer is untrusted |
| `test_strict_flag` | `strict` says whether Firefox would build the same chain |
| `test_aia_path_is_not_strict` | A chain completed through AIA is not one Firefox would build |
| `test_aia_only_used_without_trusted_path` | AIA is only used when no trusted chain exists |

**`TestEVPathBuilding`**: Extended Validation chains built first, as in Firefox

| Test | Checks that |
|---|---|
| `test_ca_specific_ev_policy_goes_through_cross_sign` | A CA-specific EV policy leads through the cross-sign to the root registered for it |
| `test_policy_order_matters` | The leaf's EV policies are tried in their order |
| `test_intermediate_must_assert_policy` | Intermediates must assert the EV policy (or anyPolicy) |
| `test_unregistered_policy_falls_back_to_cabf` | A policy not registered for any root falls back to the CA/Browser Forum EV policy |
| `test_non_ev_leaf_uses_ordinary_chain` | A leaf without EV policy gets the ordinary chain |
| `test_without_ev_data_ordinary_chain` | Without EV data, the ordinary chain is built |

**`TestFirefoxChecks`**: checks that make Firefox try other paths

| Test | Checks that |
|---|---|
| `test_expired_root_is_skipped_for_cross_sign` | An expired root is skipped and the cross-signed copy is used |
| `test_root_without_server_auth_is_skipped` | A root whose Extended Key Usage excludes TLS servers is skipped |
| `test_any_eku_intermediate_is_not_usable` | `anyExtendedKeyUsage` does not count as TLS server use |
| `test_unknown_critical_extension_makes_intermediate_unusable` | An intermediate with an unknown critical extension is skipped |
| `test_must_staple_is_inherited` | A certificate must repeat its issuer's TLS Feature (Must-Staple) extension |
| `test_leaf_problems_do_not_change_the_path` | Problems of the leaf itself (e.g. expiry) do not change the chain |
| `test_2048_bit_path_is_preferred` | A chain with 2048-bit RSA keys is preferred over one with 1024-bit keys |
| `test_self_issued_certificates_are_name_constrained` | Name constraints also apply to self-issued intermediates |

**`TestSearchBudget`**: limit on the search, as in mozilla::pkix

| Test | Checks that |
|---|---|
| `test_search_stops_when_the_budget_runs_out` | The search fails once the budget is used up |
| `test_candidates_outside_name_constraints_are_not_counted` | Candidates rejected by name constraints do not use the budget |

**`TestKeyPins`**: Firefox's static key pins

| Test | Checks that |
|---|---|
| `test_path_to_pinned_root_is_chosen` | The path through a pinned key is chosen |
| `test_no_pinned_key_is_rejected` | A chain without any pinned key is not accepted |
| `test_pins_only_apply_to_their_hosts` | Pins only apply to the hosts they are for |
| `test_test_mode_and_expired_pins_are_not_enforced` | Test-mode pins and an expired pin list are not enforced |
| `test_host_lookup` | Host and parent-domain lookup, including `includeSubdomains` |
| `test_bundled_pins` | The bundled pin list contains `addons.mozilla.org` |

### `test_trust_data.py`

The Mozilla trust data and its use during path building.

**`TestCertdataParser`**: `scripts/update_mozilla_roots.py`

| Test | Checks that |
|---|---|
| `test_trusted_roots_and_distrust_dates` | Only website-trusted roots are kept, with their distrust dates |
| `test_bundled_root_store_matches_firefox_policy` | Roots Mozilla removed (e.g. DigiCert Global Root CA) are not in the bundle; ISRG Root X1 is |

**`TestFirefoxHeaderParsers`**: `scripts/update_firefox_ct_logs.py` and `scripts/update_firefox_pins.py`

| Test | Checks that |
|---|---|
| `test_ct_logs` | CT logs, operators and expiration are read from `CTKnownLogs.h` |
| `test_pins` | Pinsets and pinned hosts are read from `StaticHPKPins.h` |

**`TestDistrustDates`**

| Test | Checks that |
|---|---|
| `test_leaf_issued_before_distrust_date` | A leaf issued before the root's distrust date is accepted |
| `test_leaf_issued_after_distrust_date_is_rejected` | A leaf issued after it is rejected |
| `test_other_path_is_used` | Another path (through another root) is used when it exists |
| `test_reported_on_the_root` | The distrust is reported as an issue on the root |

**`TestOneCRL`**

| Test | Checks that |
|---|---|
| `test_matching` | OneCRL entries match by issuer and serial, and by subject and key |
| `test_revoked_intermediate_is_skipped` | A revoked intermediate is skipped for another one |
| `test_revoked_without_alternative_is_reported` | A revoked intermediate without alternative is reported |

**`TestNameConstraints`**: name constraints as mozilla::pkix applies them

| Test | Checks that |
|---|---|
| `test_permitted_dns` | DNS names must be inside the permitted subtrees |
| `test_leading_dot_means_subdomains_only` | `.example.com` covers subdomains only |
| `test_excluded_dns` | DNS names inside an excluded subtree are rejected |
| `test_wildcards` | Wildcard names against permitted and excluded subtrees |
| `test_ip_addresses` | IP addresses against IP subtrees |
| `test_directory_name` | The subject must start with a permitted directory name |
| `test_common_name_used_without_san` | The Common Name is checked as a DNS name when there is no SAN |
| `test_excluded_directory_names_reject_everything` | Excluded directory names (unsupported by Firefox) reject every certificate |
| `test_directory_names_compare_encodings` | PrintableString and UTF8String match each other; other string types do not |
| `test_empty_subject_is_checked` | An empty subject is checked against directory-name constraints |
| `test_email_addresses` | Email addresses against host, domain and mailbox constraints |
| `test_subject_email_address_without_san` | Subject email addresses are checked when there is no SAN extension |
| `test_unsupported_name_types` | A URI is rejected only if the constraints have a URI subtree |
| `test_only_the_last_common_name_counts` | Only the most specific (last) Common Name is checked |
| `test_invalid_dns_name_is_rejected` | An invalid DNS name in the SAN is rejected |
| `test_imposed_constraints_on_tubitak_root` | NSS's imposed constraint limits the TUBITAK root to `.tr` |
| `test_path_building_avoids_violating_path` | Path building uses an unconstrained alternative |
| `test_reported_on_the_certificate` | A violation is reported on the certificate concerned |

**`TestLeafKeyUsage`**

| Test | Checks that |
|---|---|
| `test_tls_key_usages_are_accepted` | `digitalSignature`, `keyEncipherment` and `keyAgreement` are accepted |
| `test_other_key_usage_is_rejected` | Other Key Usages are rejected |
| `test_no_key_usage_is_accepted` | A leaf without Key Usage is accepted |

### `test_validation_rules.py`

The validity rules of `src/validation/` and `src/chain/certificate_rules.py`. DNS, `dig` and downloads are mocked.

**`TestIssuerRights`**

| Test | Checks that |
|---|---|
| `test_leaf_issuer_must_be_ca` | The leaf's issuer must be a CA |
| `test_issuer_without_basic_constraints` | An issuer without Basic Constraints is rejected |
| `test_issuer_key_usage` | An issuer whose Key Usage lacks `keyCertSign` is rejected |
| `test_issuer_extended_key_usage` | An issuer not allowed to issue TLS server certificates is rejected |
| `test_any_extended_key_usage_is_not_enough` | `anyExtendedKeyUsage` does not allow TLS server certificates |
| `test_path_length` | The issuer's path length constraint is enforced |
| `test_valid_leaf` | A correct leaf has no issues |

**`TestLeafChecks`**: hostname and purpose of the leaf

| Test | Checks that |
|---|---|
| `test_leaf_must_allow_server_auth` | The leaf's Extended Key Usage must include `serverAuth` |
| `test_cn_is_ignored_when_san_present` | A matching CN does not help when no SAN entry matches |
| `test_cn_is_never_used` | The CN is never used for the hostname, as in Firefox |
| `test_wildcard_matches_one_label` | A wildcard matches exactly one label |
| `test_wildcard_needs_two_labels_after_it` | `*.com` is not a valid wildcard |
| `test_only_whole_label_wildcards` | Partial (`w*.`) and multiple wildcards are rejected |
| `test_invalid_san_name_stops_matching` | An invalid DNS name in the SAN stops the search |
| `test_ip_address_matches_ip_san_only` | An IP address only matches an IP address entry |
| `test_any_extended_key_usage_leaf_is_rejected` | A leaf with only `anyExtendedKeyUsage` is rejected |
| `test_ca_certificate_as_leaf_is_rejected` | A CA certificate cannot be the leaf |
| `test_ocsp_signing_leaf_is_rejected` | A leaf that can also sign OCSP responses is rejected |
| `test_ca_certificates_are_not_hostname_checked` | CA certificates are not hostname-checked |

**`TestAlgorithms`**: Firefox's algorithm rules (NIST statuses are only reported)

| Test | Checks that |
|---|---|
| `test_rsa_1024_is_accepted_like_firefox` | A 1024-bit RSA key is valid, with the NIST status reported |
| `test_rsa_key_size_minimums` | 1024 bits is the minimum; EV and the first ordinary attempt need 2048 |
| `test_unsupported_curve_is_rejected` | Curves other than P-256/384/521 are rejected |
| `test_eddsa_key_is_rejected` | Ed25519 keys are rejected |
| `test_sha224_signature_is_rejected` | SHA-224 signatures are rejected |
| `test_rsa_pss_needs_the_standard_parameters` | RSA-PSS is only accepted with the three standard parameter sets |
| `test_signature_algorithm_must_match_inside_and_outside` | The two copies of the signature algorithm must agree |
| `test_supported_signatures` | SHA-256, SHA-384 and SHA-512 signatures are accepted |

**`TestExtensions`**

| Test | Checks that |
|---|---|
| `test_unknown_critical_extension_is_rejected` | An unknown critical extension makes the certificate invalid (not when non-critical) |
| `test_critical_key_identifiers_are_rejected` | Critical key identifier extensions are rejected, as in Firefox |
| `test_duplicate_extensions_do_not_crash` | A certificate with duplicate extensions is invalid instead of crashing the analysis |

**`TestRevocation`**: leaf revocation as Firefox checks it

| Test | Checks that |
|---|---|
| `test_crl_revoked` | A certificate listed in its CRL is revoked |
| `test_crl_is_final` | A usable CRL decides; OCSP and the stapled response are not consulted |
| `test_forged_crl_is_ignored` | A CRL not signed by the issuer is ignored |
| `test_ocsp_uses_sha1_and_detects_revocation` | OCSP requests use SHA-1 and detect revocation |
| `test_ocsp_good` | A good OCSP answer is accepted |
| `test_forged_ocsp_response_is_ignored` | An OCSP response signed by an unauthorised certificate is ignored |
| `test_unsuccessful_ocsp_answer_is_reported` | Unsuccessful OCSP answers give a warning |
| `test_fetch_errors_do_not_leak_details` | Download errors are reported without internal details |
| `test_missing_revocation_info_is_only_a_warning` | A certificate without CRL or OCSP information only gets a warning |
| `test_short_lived_certificate_is_not_queried` | Certificates valid for less than 10 days are not queried |
| `test_expired_certificate_is_not_checked` | Expired certificates are not checked for revocation |
| `test_stapled_good_response` | A good stapled response is accepted |
| `test_stapled_revoked_response` | A revoked stapled response makes the leaf invalid |
| `test_stapled_unknown_or_forged_response_is_rejected` | Unknown, badly signed, future-dated or malformed stapled responses are rejected |
| `test_expired_stapled_response_is_ignored_whatever_it_says` | An expired stapled response is ignored, even if revoked |
| `test_expired_revoked_response_from_the_network_counts` | An expired "revoked" from the OCSP server still counts |
| `test_tolerated_stapled_responses_are_ignored` | Expired responses and responses about another certificate are ignored |
| `test_expired_crl_does_not_prove_good_standing` | An expired CRL does not prove the certificate is not revoked |
| `test_expired_crl_listing_the_certificate` | An expired CRL listing the certificate still makes it revoked |
| `test_partial_crls_do_not_prove_good_standing` | CA-only, reason-limited, delta and indirect CRLs are not final |
| `test_end_entity_crl_with_distribution_point_is_final` | A complete end-entity CRL is final |
| `test_stapled_scts_only_when_the_response_was_used` | SCTs of the stapled response only count when it was used |
| `test_delegated_responder_must_pass_firefox_checks` | A delegated OCSP responder must pass Firefox's certificate checks |
| `test_crls_are_downloaded_once` | A CRL is downloaded once and then reused from the cache |
| `test_cached_crl_expires` | Cached CRLs expire at their next update or after at most one hour |
| `test_failures_and_expired_crls_are_not_cached` | Failed downloads and expired CRLs are not cached |
| `test_ocsp_responses_are_reused_for_the_same_certificate` | OCSP responses are reused only for the same certificate |
| `test_unsuccessful_ocsp_answers_are_not_cached` | Unsuccessful OCSP answers are not cached |
| `test_delegated_responder` | A responder authorised by the issuer may sign responses |
| `test_response_with_several_certificates` | An OCSP response about several certificates does not crash |
| `test_cert_id_key_hash_matches_cryptography` | The OCSP issuer key hash is computed correctly |
| `test_intermediates_are_not_checked_online` | Intermediates are not checked against CRLs or OCSP (OneCRL only) |

**`TestMustStaple`**

| Test | Checks that |
|---|---|
| `test_missing_stapled_response` | A Must-Staple certificate without a stapled response is invalid |
| `test_stapled_response_present` | It is accepted when a response is stapled |

**`TestSafeFetch`**: URLs from certificates cannot reach internal systems

| Test | Checks that |
|---|---|
| `test_internal_addresses_are_refused` | Local and private addresses are refused |
| `test_only_http_is_fetched` | Only `http://` URLs are fetched |
| `test_dns_answer_with_private_address_is_refused` | A host name resolving to a private address is refused |

**`TestChainStatus`**

| Test | Checks that |
|---|---|
| `test_chain_firefox_would_reject_is_invalid` | A chain Firefox would not build is invalid, with a note |
| `test_ipv6_only_domain` | IPv6-only domains get their IPv6 address instead of a crash |

**`TestDnssec`**

| Test | Checks that |
|---|---|
| `test_validated` | A DNSSEC-validated answer gives no warning |
| `test_not_validated` | A non-validated answer gives a warning |
| `test_result_computed_in_parallel_is_used` | The DNSSEC result computed in parallel is used without running `dig` again |
| `test_resolver_unreachable` | An unreachable resolver gives "could not be checked", not "failed" |

### `test_transparency.py`

Certificate Transparency (`src/validation/transparency.py`) and the TLS handshake (`src/fetch/tls.py`), with generated CT logs and SCTs.

**`TestEmbeddedSCTs`**

| Test | Checks that |
|---|---|
| `test_two_operators_are_compliant` | Two SCTs from logs of two operators meet the policy |
| `test_one_sct_is_not_enough` | One SCT is not enough |
| `test_same_operator_is_not_diverse` | Two SCTs from the same operator are not enough |
| `test_long_lived_certificates_need_three` | Certificates valid for more than 180 days need three SCTs |
| `test_unknown_log_does_not_count` | SCTs from unknown logs do not count |
| `test_bad_signature_does_not_count` | SCTs with a bad signature do not count |
| `test_retired_log` | A retired log counts only if retired after issuance |
| `test_retired_logs_alone_are_not_enough` | At least one SCT must come from an admissible log |
| `test_tiled_logs_need_a_leaf_index` | SCTs from tiled logs need a leaf index |
| `test_future_and_distrusted_timestamps_do_not_count` | Future-dated SCTs, and SCTs after the root's distrust date, do not count |
| `test_not_enforced_when_the_log_list_expired` | CT is not enforced once the log list has expired |
| `test_chain_of_one_certificate_is_not_compliant` | A chain without issuer cannot comply |

**`TestDeliveredSCTs`**: SCTs sent in the handshake or the OCSP response

| Test | Checks that |
|---|---|
| `test_two_tls_scts_are_compliant` | Two SCTs from the TLS handshake meet the policy |
| `test_tls_and_ocsp_scts_combine` | SCTs from the handshake and the OCSP response combine |
| `test_sct_for_another_certificate` | SCTs for another certificate are invalid |
| `test_malformed_lists` | Malformed SCT lists are counted as errors |

**`TestChainLevel`**

| Test | Checks that |
|---|---|
| `test_non_compliant_leaf_is_invalid` | A non-compliant leaf makes the chain invalid |
| `test_expired_log_list_is_reported` | An expired log list is reported in the analysis |
| `test_bundled_log_list` | The bundled CT log list loads with several operators |

**`TestHandshakeParsing`**: reading `openssl s_client -msg` output

| Test | Checks that |
|---|---|
| `test_tls13_certificate_entry_extensions` | The stapled response and SCTs are read from a TLS 1.3 Certificate message |
| `test_tls12_server_hello_and_certificate_status` | They are read from TLS 1.2 ServerHello and CertificateStatus messages |
| `test_nothing_sent` | Nothing is returned when the server sends neither |
| `test_only_the_chain_section_holds_the_certificates` | Certificates printed elsewhere (e.g. the OCSP responder's) are not taken as the chain |
| `test_truncated_message_is_ignored` | Truncated messages are ignored |

**`TestFirefoxClientHello`**

| Test | Checks that |
|---|---|
| `test_post_quantum_group_and_key_shares` | X25519MLKEM768 is offered with Firefox's key shares when OpenSSL supports it |
| `test_older_openssl_gets_classical_groups` | Older OpenSSL versions offer the classical groups |
| `test_only_tls_1_2_and_1_3` | The Firefox-like handshake only offers TLS 1.2 and 1.3 |
| `test_last_fallback_has_no_post_quantum_key_share` | The legacy fallback offers no post-quantum key share |
| `test_ecdsa_cbc_suites_are_not_offered` | The ECDSA CBC suites Firefox disables are not offered |

### `test_signatures.py`

Signature verification (`src/chain/signatures.py`).

| Test | Checks that |
|---|---|
| `TestSignatureCheck.test_rsa_pkcs1v15` | RSA PKCS#1 v1.5 signatures verify |
| `TestSignatureCheck.test_rsa_pss` | RSA-PSS signatures verify |
| `TestSignatureCheck.test_ecdsa` | ECDSA signatures verify |
| `TestSignatureCheck.test_ed25519` | Ed25519 signatures verify |
| `TestSignatureCheck.test_self_signed_root` | A self-signed root verifies with its own key |
| `TestSignatureCheck.test_wrong_key` | A signature from another key fails |
| `TestSignatureCheck.test_wrong_issuer_name` | A mismatching issuer name fails |
| `TestSignatureCheck.test_mismatched_key_type` | An issuer key of the wrong type fails cleanly |
| `TestSha1Roots.test_sha1_roots_are_self_signed` | Mozilla roots signed with SHA-1 verify, and are flagged as SHA-1 |
| `TestSha1Roots.test_sha1_root_is_valid` | Such a root is still valid (a root's self-signature is not relied upon) |

### `test_nist_parser.py`

NIST classification (`src/validation/nist/parser.py`) and how it is reported.

| Test | Checks that |
|---|---|
| `TestKeyStatus.test_rsa` | RSA key sizes get the right status |
| `TestKeyStatus.test_dsa_is_disallowed` | DSA is disallowed |
| `TestKeyStatus.test_eddsa` | EdDSA keys are acceptable |
| `TestKeyStatus.test_nist_prime_curves` | NIST prime curves are acceptable |
| `TestKeyStatus.test_p192_is_disallowed` | P-192 is not acceptable |
| `TestKeyStatus.test_deprecated_binary_curve` | Large binary curves are deprecated |
| `TestKeyStatus.test_small_binary_curve` | Small binary curves are not acceptable |
| `TestKeyStatus.test_brainpool_is_allowed` | Brainpool curves are acceptable |
| `TestKeyStatus.test_secp256k1_is_disallowed` | secp256k1 is disallowed |
| `TestHashStatus.test_hashes` | Each hash function gets the right status |
| `TestHashStatus.test_missing_hash_is_unsupported` | A hash not in the table is reported as unsupported |
| `TestSignatureHashReporting.test_eddsa_signature_has_no_hash_issue` | EdDSA signatures get no hash issue |
| `TestSignatureHashReporting.test_root_self_signature_hash_is_not_checked` | A root's self-signature hash is not reported |
| `TestSignatureHashReporting.test_sha1_signature_is_reported_on_other_certificates` | SHA-1 is reported on other certificates |

### `test_certificate_fields.py`

The `validation_level` field (`src/validation/certificate_fields.py`).

| Test | Checks that |
|---|---|
| `TestValidationLevel.test_ev_policy` | The EV policy gives EV |
| `TestValidationLevel.test_ov_policy` | The OV policy gives OV |
| `TestValidationLevel.test_dv_policy_wins_over_organization` | The DV policy gives DV even with an Organization in the subject |
| `TestValidationLevel.test_highest_policy_wins` | With several policies, the highest level wins |
| `TestValidationLevel.test_other_policies_are_ignored` | Other policies are ignored |
| `TestValidationLevel.test_fallback_without_policy` | Without a policy, OV if the subject has an Organization, DV otherwise |

### `test_client.py`

How cert-info behaves toward the servers it contacts (`src/fetch/client.py`). Requests are mocked.

| Test | Checks that |
|---|---|
| `TestRetryAfter.test_seconds_and_dates` | `Retry-After` in seconds and as a date is understood |
| `TestRetryAfter.test_missing_or_invalid_uses_default` | A missing or invalid `Retry-After` gives 60 seconds |
| `TestRetryAfter.test_bounds` | The delay is between 0 and one hour |
| `TestRetryAfter.test_back_off_expires` | The back-off ends when the delay has passed |
| `TestRetryAfter.test_only_429_and_503` | Only 429 and 503 trigger a back-off |
| `TestHttpsProbe.test_honest_user_agent_and_no_body` | The probe sends cert-info's User-Agent and does not download the page |
| `TestHttpsProbe.test_rate_limited_server_is_not_probed_again` | After 429, the server is not probed again; the previous answer is reused |
| `TestHttpsProbe.test_unavailable_server` | The same after 503 |
| `TestHttpsProbe.test_other_statuses_do_not_back_off` | Other statuses do not stop later probes |
| `TestCertificateUrls.test_user_agent` | CRL/OCSP/AIA downloads send cert-info's User-Agent |
| `TestCertificateUrls.test_rate_limited_server_is_not_contacted_again` | After 429, the server is not contacted again until the delay has passed |

### `test_firefox_comparison.py`

Compares cert-info with a real Firefox on the top domains of a [Tranco](https://tranco-list.eu) list. A headless Firefox requests each domain (stopping at the response headers) and the test reads the certificates the server sent and the chain Firefox built.

Requirements: Firefox, network access and Selenium (`requirements-dev.txt`). It takes about one minute for 250 domains and is skipped unless enabled:

```bash
CERTINFO_FIREFOX_TEST=1 python -m unittest tests.test_firefox_comparison -v
```

| Test | Checks that |
|---|---|
| `TestFirefoxComparison.test_intermediates_were_preloaded` | Firefox's preloaded intermediates were downloaded before the comparison |
| `TestFirefoxComparison.test_path_building_matches_firefox` | Given the certificates Firefox received, cert-info builds Firefox's chain |
| `TestFirefoxComparison.test_untrusted_chains_are_rejected` | When Firefox finds no trusted chain, neither does cert-info |
| `TestFirefoxComparison.test_end_to_end_matches_firefox` | When cert-info fetches the certificates itself and receives the same leaf, the chains are equal |

Environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `CERTINFO_FIREFOX_TEST` | not set | `1` to run the comparison |
| `CERTINFO_TRANCO_LIST` | `JZPGY` | Tranco list ID (fixed so runs are comparable) |
| `CERTINFO_TRANCO_TOP` | `250` | Number of domains |
| `CERTINFO_FIREFOX_BINARY` | found automatically | Path to the Firefox executable |
| `CERTINFO_FIREFOX_CONCURRENCY` | `24` | Requests Firefox makes at the same time |
| `CERTINFO_FIREFOX_REPORT` | `firefox_comparison.json` | JSON report with every domain's chains |

Some domains are expected to differ end to end even when cert-info is right: when a site redirects (e.g. `instagram.com` to `www.instagram.com`) and the first certificate also covers the new host, Firefox reuses its connection, while cert-info opens a new one to the final host and may receive a different leaf.
