"""
TLS/SSL Configuration Factory

Creates properly configured SSL contexts for:
  - Server-side TLS (accepts encrypted client connections)
  - Client-side TLS (connects to encrypted servers)
  - Mutual TLS (mTLS) where both sides present certificates
  - Proxy TLS (dual contexts for the inspection proxy)

This mirrors Zscaler's dual-handshake architecture:
  Client ──[TLS handshake 1]──> Proxy ──[TLS handshake 2]──> Server

Security Posture:
  - TLS 1.2+ enforced (TLS 1.0/1.1 disabled)
  - Strong cipher suites only
  - Certificate verification against the CA trust chain
  - Optional mutual TLS for client certificate authentication
"""

import os
import ssl
import logging

log = logging.getLogger(__name__)

# Default certificate paths (relative to project root)
DEFAULT_CERT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "certs")

# Paths to certificate files
CERT_PATHS = {
    'ca_cert':     os.path.join(DEFAULT_CERT_DIR, "ca_cert.pem"),
    'server_cert': os.path.join(DEFAULT_CERT_DIR, "server_cert.pem"),
    'server_key':  os.path.join(DEFAULT_CERT_DIR, "server_key.pem"),
    'client_cert': os.path.join(DEFAULT_CERT_DIR, "client_cert.pem"),
    'client_key':  os.path.join(DEFAULT_CERT_DIR, "client_key.pem"),
    'proxy_cert':  os.path.join(DEFAULT_CERT_DIR, "proxy_cert.pem"),
    'proxy_key':   os.path.join(DEFAULT_CERT_DIR, "proxy_key.pem"),
}


def _check_certs_exist(required_files: list) -> bool:
    """Verify that all required certificate files exist."""
    for filepath in required_files:
        if not os.path.exists(filepath):
            log.warning(f"Certificate file not found: {filepath}")
            return False
    return True


def create_server_ssl_context(
    require_client_cert: bool = False,
    cert_dir: str = None,
) -> ssl.SSLContext:
    """
    Create an SSL context for the server side.

    This context:
      - Loads the server's certificate and private key
      - Trusts the CA certificate for verifying client certs (if mTLS)
      - Enforces TLS 1.2+
      - Uses strong cipher suites

    Args:
        require_client_cert: If True, requires clients to present a valid
                            certificate signed by the CA (mutual TLS).
        cert_dir: Override path to the certificates directory.

    Returns:
        A configured ssl.SSLContext for server use.
    """
    paths = dict(CERT_PATHS)
    if cert_dir:
        paths = {k: os.path.join(cert_dir, os.path.basename(v)) for k, v in paths.items()}

    required = [paths['ca_cert'], paths['server_cert'], paths['server_key']]
    if not _check_certs_exist(required):
        log.error("Server certificates not found. Run: python -m security.cert_generator")
        raise FileNotFoundError(
            "TLS certificates not found. Generate them with: "
            "python -m security.cert_generator"
        )

    # Create server-side context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Security hardening: minimum TLS 1.2
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    # Load server certificate chain
    context.load_cert_chain(
        certfile=paths['server_cert'],
        keyfile=paths['server_key'],
    )

    # Load the CA certificate for verifying client certificates
    context.load_verify_locations(cafile=paths['ca_cert'])

    if require_client_cert:
        # Mutual TLS: require client certificate
        context.verify_mode = ssl.CERT_REQUIRED
        log.info("Server SSL context created with MUTUAL TLS (mTLS) — client certs required")
    else:
        # Standard TLS: no client cert needed
        context.verify_mode = ssl.CERT_NONE
        log.info("Server SSL context created with standard TLS")

    return context


def create_client_ssl_context(
    use_client_cert: bool = False,
    verify_server: bool = True,
    cert_dir: str = None,
) -> ssl.SSLContext:
    """
    Create an SSL context for the client side.

    This context:
      - Trusts the CA certificate for verifying the server
      - Optionally loads a client certificate for mTLS
      - Enforces TLS 1.2+

    Args:
        use_client_cert: If True, loads the client certificate and key
                        for mutual TLS authentication.
        verify_server: If True, verifies the server's certificate against
                      the CA. Set to False only for testing.
        cert_dir: Override path to the certificates directory.

    Returns:
        A configured ssl.SSLContext for client use.
    """
    paths = dict(CERT_PATHS)
    if cert_dir:
        paths = {k: os.path.join(cert_dir, os.path.basename(v)) for k, v in paths.items()}

    required = [paths['ca_cert']]
    if use_client_cert:
        required.extend([paths['client_cert'], paths['client_key']])

    if not _check_certs_exist(required):
        log.error("Client certificates not found. Run: python -m security.cert_generator")
        raise FileNotFoundError(
            "TLS certificates not found. Generate them with: "
            "python -m security.cert_generator"
        )

    # Create client-side context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Security hardening: minimum TLS 1.2
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    if verify_server:
        # Load CA cert to verify server's certificate
        context.load_verify_locations(cafile=paths['ca_cert'])
        context.check_hostname = False  # We use IP addresses, not hostnames
        context.verify_mode = ssl.CERT_REQUIRED
    else:
        # Disable verification (testing only!)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        log.warning("CLIENT SSL: Server verification DISABLED (testing mode)")

    if use_client_cert:
        # Load client certificate for mTLS
        context.load_cert_chain(
            certfile=paths['client_cert'],
            keyfile=paths['client_key'],
        )
        log.info("Client SSL context created with mutual TLS (client cert loaded)")
    else:
        log.info("Client SSL context created with standard TLS")

    return context


def create_proxy_ssl_contexts(cert_dir: str = None) -> tuple:
    """
    Create DUAL SSL contexts for the TLS inspection proxy.

    This mirrors Zscaler's Zero Trust Exchange dual-handshake:
      1. Server-side context: proxy acts as a TLS server to accept client connections
      2. Client-side context: proxy acts as a TLS client to connect to the real server

    The proxy terminates the client's TLS, inspects the plaintext data,
    then re-encrypts and forwards to the actual server.

    Args:
        cert_dir: Override path to the certificates directory.

    Returns:
        (proxy_server_ctx, proxy_client_ctx) — the two SSL contexts
    """
    paths = dict(CERT_PATHS)
    if cert_dir:
        paths = {k: os.path.join(cert_dir, os.path.basename(v)) for k, v in paths.items()}

    # Context 1: Proxy acts as SERVER (accepts client connections)
    proxy_server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    proxy_server_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    proxy_server_ctx.load_cert_chain(
        certfile=paths['proxy_cert'],
        keyfile=paths['proxy_key'],
    )
    proxy_server_ctx.load_verify_locations(cafile=paths['ca_cert'])
    proxy_server_ctx.verify_mode = ssl.CERT_NONE  # Don't require client certs at proxy

    # Context 2: Proxy acts as CLIENT (connects to real server)
    proxy_client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    proxy_client_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    proxy_client_ctx.load_verify_locations(cafile=paths['ca_cert'])
    proxy_client_ctx.check_hostname = False
    proxy_client_ctx.verify_mode = ssl.CERT_REQUIRED

    log.info("Proxy DUAL SSL contexts created (server-facing + client-facing)")
    return proxy_server_ctx, proxy_client_ctx


def get_tls_info(ssl_object) -> dict:
    """
    Extract TLS session information from an SSL socket/transport.
    Useful for audit logging.

    Returns a dict with TLS version, cipher, and peer cert info.
    """
    info = {}
    try:
        if hasattr(ssl_object, 'version'):
            info['tls_version'] = ssl_object.version()
        if hasattr(ssl_object, 'cipher'):
            cipher = ssl_object.cipher()
            if cipher:
                info['cipher_suite'] = cipher[0]
                info['cipher_protocol'] = cipher[1]
                info['cipher_bits'] = cipher[2]
        if hasattr(ssl_object, 'getpeercert'):
            peer_cert = ssl_object.getpeercert()
            if peer_cert:
                # Extract the Common Name from the subject
                for rdn in peer_cert.get('subject', ()):
                    for attr_type, attr_value in rdn:
                        if attr_type == 'commonName':
                            info['peer_cn'] = attr_value
                info['peer_serial'] = peer_cert.get('serialNumber', 'N/A')
                info['peer_not_after'] = peer_cert.get('notAfter', 'N/A')
    except Exception as e:
        info['error'] = str(e)
    return info
