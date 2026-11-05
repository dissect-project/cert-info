"""
Entry point of the analysis: checks the domain, retrieves the certificates
sent by its server, builds the chain the way Firefox does and validates it.

    src/fetch/        talking to the analysed server
    src/trust/        Mozilla trust data
    src/chain/        building the chain like Firefox
    src/validation/   judging the chain and its certificates
"""

from concurrent.futures import ThreadPoolExecutor

from src.fetch import https_probe
from src.fetch.domain import DEFAULT_PORT, is_reachable, is_valid_domain, split_host_port
from src.fetch.tls import fetch_handshake
from src.validation.certificate_validator import check_dnssec
from src.validation.chain_validator import ChainValidator

# Runs the DNSSEC lookups (dig), which only need the host name, while the rest
# of the analysis goes on
_background = ThreadPoolExecutor(max_workers=16, thread_name_prefix="dnssec")


class CertificateInformation:
    """Analyze the certificate chain of a domain."""

    def is_valid(self, domain: str) -> bool:
        """Check that the domain is well formed (optional scheme and port)."""
        return is_valid_domain(domain)

    def is_reachable(self, domain: str, port: int = DEFAULT_PORT) -> bool:
        """Check that a TCP connection to the domain can be opened."""
        return is_reachable(domain, port)

    def supports_https(self, host: str, port: int = DEFAULT_PORT) -> tuple[bool | None, str, int]:
        """See src/fetch/https_probe.py."""
        return https_probe.supports_https(host, port)

    def analyze(self, domain: str, show_cert: bool = False, force: bool = False) -> dict:
        """
        Analyze the certificate chain of a domain.

        Args:
            domain (str): The domain to analyze.
            show_cert (bool): Include the decoded certificate fields.
            force (bool): Analyze even if the domain is unreachable or the
                HTTPS probe fails.

        Returns:
            dict: The analysis, or {"status": "error", "error": message}.
        """
        if not self.is_valid(domain):
            return _error("Invalid domain.")
        original_host, port = split_host_port(domain)
        if port is None:
            return _error("Invalid port number.")
        dnssec = _background.submit(check_dnssec, original_host)
        if not self.is_reachable(original_host, port) and not force:
            return _error("Domain is not reachable.")

        https_supported, host, port = self.supports_https(original_host, port)
        if host != original_host:
            # Redirected: the DNSSEC check is about the analysed host
            dnssec.cancel()
            dnssec = _background.submit(check_dnssec, host)
        # The HTTP probe only decides which error to report. The chain comes from
        # the TLS handshake, which often succeeds when the HTTP layer blocks or
        # fails (e.g. bot protection answering with 503).
        if https_supported is None:
            probe_error = "Domain is not reachable."
        elif not https_supported and not force:
            probe_error = "Domain does not support HTTPS."
        else:
            probe_error = None

        try:
            handshake = fetch_handshake(host, port)
            if not handshake.certificates:
                return _error(probe_error or "Failed to retrieve certificate chain.")
            chain, extra, trusted, strict = ChainValidator.build_chain(handshake.certificates, hostname=host)
            if not chain:
                return _error("Failed to retrieve certificate chain.")
            redirected = host != original_host
            return ChainValidator.validate_chain(
                host, chain, extra, trusted, show_cert,
                original_domain=original_host if redirected else None,
                strict=strict, handshake=handshake, dnssec=dnssec
            )
        except KeyboardInterrupt:
            return _error("Scan interrupted.")


def _error(message: str) -> dict:
    """Build an error response."""
    return {"status": "error", "error": message}
