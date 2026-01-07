import socket
from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
from datetime import datetime

def retrieve_and_validate_cert_chain(domain, port=443):
    """
    Retrieves the certificate chain from a given domain and validates it.

    Args:
        domain (str): The domain name to connect to.
        port (int): The port to connect to (default: 443).

    Returns:
        list: A list of PEM-encoded unique and ordered certificates in the chain,
              or None if validation fails or connection errors occur.
    """
    cert_chain_raw = []
    try:
        # Retrieve the certificate chain using OpenSSL
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        # It's generally a good idea to disable OpenSSL's internal verification
        # here if you plan to do your own robust validation afterwards.
        # context.set_verify(SSL.VERIFY_NONE, None) # Uncomment if you want to disable internal OpenSSL verification

        conn = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        conn.set_tlsext_host_name(domain.encode())
        conn.connect((domain, port))
        conn.set_connect_state()
        conn.do_handshake()

        # Retrieve the full certificate chain from the connection
        for cert_obj in conn.get_peer_cert_chain():
            cert_chain_raw.append(cert_obj)

        # Also get the leaf certificate (the first one in the chain)
        leaf_cert_obj = conn.get_peer_certificate()
        if leaf_cert_obj and leaf_cert_obj not in cert_chain_raw:
            cert_chain_raw.insert(0, leaf_cert_obj) # Ensure leaf is at the start if not already there

    except SSL.Error as e:
        print(f"SSL Error during connection or handshake: {e}")
        return None
    except socket.error as e:
        print(f"Socket error during connection: {e}")
        return None
    finally:
        if 'conn' in locals() and conn:
            conn.close()

    if not cert_chain_raw:
        print("No certificate chain retrieved.")
        return None

    # --- Process and Validate the Chain ---

    # 1. Convert to cryptography X509 objects and remove duplicates
    unique_certs = {}
    for cert_obj in cert_chain_raw:
        # Use a unique identifier (e.g., subject and serial number) to prevent duplicates
        cert_cryptography = cert_obj.to_cryptography()
        cert_identifier = (cert_cryptography.subject.rfc4514_string(), cert_cryptography.serial_number)
        unique_certs[cert_identifier] = cert_cryptography
    
    # Sort certificates: The leaf certificate should usually be the one whose subject matches the domain,
    # and subsequent certificates should be its issuer, and so on.
    # A more robust sorting would involve checking subject/issuer names.
    # For now, we'll rely on the order provided by get_peer_cert_chain,
    # and ensure the leaf cert is in place for validation.

    processed_certs = list(unique_certs.values())

    # Find the actual leaf certificate that matches the domain (or is the first in the chain)
    leaf_cert = None
    if processed_certs:
        # The first cert in the chain is usually the leaf (server's certificate)
        leaf_cert = processed_certs[0] 
        # You might add more sophisticated logic here to find the actual leaf if needed,
        # e.g., by checking Common Name or Subject Alternative Names against the domain.

    if not leaf_cert:
        print("Could not identify the leaf certificate.")
        return None

    # Separate the leaf from intermediate certificates
    untrusted_intermediates = [cert for cert in processed_certs if cert != leaf_cert]

    # 2. Build a trusted store (using certifi for common CAs)
    # You might want to use your system's CA bundle or a custom one.
    # For a cross-platform solution, 'certifi' is very useful.
    try:
        import certifi
        with open(certifi.where(), "rb") as f:
            trusted_pem_bytes = f.read()
    except ImportError:
        print("Certifi not found. Using an empty trusted store for demonstration. "
              "Consider installing 'certifi' or providing your own CA bundle.")
        trusted_pem_bytes = b""
    except FileNotFoundError:
        print(f"Certifi CA bundle not found at {certifi.where()}. "
              "Ensure certifi is correctly installed.")
        trusted_pem_bytes = b""

    trusted_certs = x509.load_pem_x509_certificates(trusted_pem_bytes, default_backend())

    store = Store()
    for trusted_cert in trusted_certs:
        store = store.add_trusted_cert(trusted_cert)

    # 3. Validate the chain using cryptography
    builder = PolicyBuilder().any_policy()
    verifier = builder.build_verifier(store)

    try:
        # This function handles ordering, duplicates (implicitly by building a path),
        # and verifies signatures and validity periods.
        # The `untrusted_intermediates` are the candidates for building the chain.
        # `peer` is the leaf certificate.
        # The `valid_path` will be a list of certificates from leaf to root.
        valid_path = verifier.verify(peer=leaf_cert, untrusted_intermediates=untrusted_intermediates)
        
        # Convert the valid path to PEM format
        final_chain_pem = []
        for cert in valid_path:
            pem_cert = cert.public_bytes(serialization.Encoding.PEM)
            final_chain_pem.append(pem_cert.decode())
        
        return final_chain_pem

    except VerificationError as e:
        print(f"Certificate chain validation failed: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during validation: {e}")
        return None

# Example Usage:
if __name__ == "__main__":
    # You might need to install 'pyOpenSSL' and 'cryptography' and 'certifi':
    # pip install pyOpenSSL cryptography certifi

    test_domains = [
        ("www.scmp.pt", 443),
        ("self-signed.badssl.com", 443), # Example of a site with a self-signed cert (will likely fail validation)
        ("expired.badssl.com", 443), # Example of a site with an expired cert (will likely fail validation)
        ("httpbin.org", 443)
    ]

    for domain, port in test_domains:
        print(f"\n--- Checking {domain}:{port} ---")
        chain = retrieve_and_validate_cert_chain(domain, port)
        if chain:
            print(f"Successfully retrieved and validated chain for {domain}:")
            for i, cert_pem in enumerate(chain):
                # Load back to cryptography object to print subject/issuer
                cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                print(f"  Cert {i}: Subject: {cert.subject.rfc4514_string()}, Issuer: {cert.issuer.rfc4514_string()}")
        else:
            print(f"Failed to retrieve or validate certificate chain for {domain}.")