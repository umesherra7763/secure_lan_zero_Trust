"""
X.509 Certificate Generator for TLS/mTLS Infrastructure

Generates a complete PKI (Public Key Infrastructure) hierarchy:
  - Root Certificate Authority (CA) — self-signed trust anchor
  - Server Certificate — signed by CA, used by the communication server
  - Client Certificate — signed by CA, used for mutual TLS (mTLS)
  - Proxy Certificate — signed by CA, used by the TLS inspection proxy

This mirrors how Zscaler's Zero Trust Exchange operates:
  - Enterprise deploys a trusted Root CA on all endpoints
  - Zscaler proxy dynamically generates certificates signed by this CA
  - Clients trust the proxy because they trust the CA

Usage:
    python -m security.cert_generator
    # or
    from security.cert_generator import CertificateGenerator
    CertificateGenerator.generate_all()
"""

import os
import datetime
import logging

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

log = logging.getLogger(__name__)

# Default output directory for certificates
DEFAULT_CERT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "certs")


class CertificateGenerator:
    """
    Generates a complete PKI hierarchy for the communication suite.

    The hierarchy is:
        Root CA (self-signed)
         ├── Server Certificate (for the main server)
         ├── Client Certificate (for mTLS client auth)
         └── Proxy Certificate  (for the TLS inspection proxy)
    """

    # Certificate validity periods
    CA_VALIDITY_DAYS = 3650       # 10 years
    CERT_VALIDITY_DAYS = 365      # 1 year

    # RSA key sizes
    CA_KEY_SIZE = 4096            # Stronger key for CA
    CERT_KEY_SIZE = 2048          # Standard for leaf certs

    def __init__(self, cert_dir: str = DEFAULT_CERT_DIR):
        self.cert_dir = cert_dir
        os.makedirs(self.cert_dir, exist_ok=True)

    def _generate_private_key(self, key_size: int) -> rsa.RSAPrivateKey:
        """Generate an RSA private key."""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

    def _save_private_key(self, key: rsa.RSAPrivateKey, filename: str) -> str:
        """Save a private key to PEM file. Returns the filepath."""
        filepath = os.path.join(self.cert_dir, filename)
        with open(filepath, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        log.info(f"Saved private key: {filepath}")
        return filepath

    def _save_certificate(self, cert: x509.Certificate, filename: str) -> str:
        """Save a certificate to PEM file. Returns the filepath."""
        filepath = os.path.join(self.cert_dir, filename)
        with open(filepath, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        log.info(f"Saved certificate: {filepath}")
        return filepath

    def generate_ca(self) -> tuple:
        """
        Generate a self-signed Root Certificate Authority.

        Returns:
            (ca_key, ca_cert) — the CA private key and certificate
        """
        log.info("Generating Root Certificate Authority...")

        ca_key = self._generate_private_key(self.CA_KEY_SIZE)

        # Build the CA subject/issuer (same for self-signed)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Karnataka"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureLAN Communications"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Zero Trust Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, "SecureLAN Root CA"),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)

        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=self.CA_VALIDITY_DAYS))
            # CA-specific extensions
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        self._save_private_key(ca_key, "ca_key.pem")
        self._save_certificate(ca_cert, "ca_cert.pem")

        log.info("Root CA generated successfully.")
        return ca_key, ca_cert

    def generate_signed_cert(
        self,
        ca_key: rsa.RSAPrivateKey,
        ca_cert: x509.Certificate,
        common_name: str,
        san_dns: list = None,
        san_ips: list = None,
        is_server: bool = True,
        key_filename: str = "cert_key.pem",
        cert_filename: str = "cert.pem",
    ) -> tuple:
        """
        Generate a certificate signed by the CA.

        Args:
            ca_key: CA private key for signing
            ca_cert: CA certificate (issuer)
            common_name: CN for the certificate
            san_dns: List of DNS SANs (e.g., ["localhost"])
            san_ips: List of IP SANs (e.g., ["127.0.0.1", "192.168.1.1"])
            is_server: True for server cert (TLS Web Server Auth),
                       False for client cert (TLS Web Client Auth)
            key_filename: Output filename for private key
            cert_filename: Output filename for certificate

        Returns:
            (cert_key, cert) — the certificate's private key and certificate
        """
        log.info(f"Generating {'server' if is_server else 'client'} certificate: {common_name}")

        cert_key = self._generate_private_key(self.CERT_KEY_SIZE)

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Karnataka"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureLAN Communications"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(cert_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=self.CERT_VALIDITY_DAYS))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
        )

        # Extended Key Usage — server or client authentication
        if is_server:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
        else:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )

        # Subject Alternative Names (SANs) — critical for TLS validation
        san_list = []
        if san_dns:
            for dns in san_dns:
                san_list.append(x509.DNSName(dns))
        if san_ips:
            import ipaddress
            for ip in san_ips:
                san_list.append(x509.IPAddress(ipaddress.ip_address(ip)))

        if san_list:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )

        # Key Usage for leaf certificates
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        cert = builder.sign(ca_key, hashes.SHA256())

        self._save_private_key(cert_key, key_filename)
        self._save_certificate(cert, cert_filename)

        log.info(f"Certificate '{common_name}' generated and signed by CA.")
        return cert_key, cert

    @classmethod
    def generate_all(cls, cert_dir: str = DEFAULT_CERT_DIR, server_ip: str = "127.0.0.1"):
        """
        Generate the complete PKI hierarchy:
          - Root CA
          - Server certificate (with localhost + LAN IP SANs)
          - Client certificate (for mTLS)
          - Proxy certificate (for the TLS inspection proxy)

        Args:
            cert_dir: Directory to write certificates to
            server_ip: The server's LAN IP address to include as a SAN
        """
        gen = cls(cert_dir)

        # 1. Generate Root CA
        ca_key, ca_cert = gen.generate_ca()

        # 2. Generate Server Certificate
        #    SANs include localhost and the LAN IP so clients can connect
        #    via either address.
        server_sans_dns = ["localhost"]
        server_sans_ips = ["127.0.0.1"]
        if server_ip and server_ip not in server_sans_ips:
            server_sans_ips.append(server_ip)

        gen.generate_signed_cert(
            ca_key, ca_cert,
            common_name="SecureLAN Server",
            san_dns=server_sans_dns,
            san_ips=server_sans_ips,
            is_server=True,
            key_filename="server_key.pem",
            cert_filename="server_cert.pem",
        )

        # 3. Generate Client Certificate (for mTLS)
        gen.generate_signed_cert(
            ca_key, ca_cert,
            common_name="SecureLAN Client",
            is_server=False,
            key_filename="client_key.pem",
            cert_filename="client_cert.pem",
        )

        # 4. Generate Proxy Certificate
        #    The proxy acts as both a server (to clients) and a client (to server)
        #    so it gets SANs matching the server for impersonation.
        gen.generate_signed_cert(
            ca_key, ca_cert,
            common_name="SecureLAN TLS Inspection Proxy",
            san_dns=["localhost"],
            san_ips=["127.0.0.1"],
            is_server=True,
            key_filename="proxy_key.pem",
            cert_filename="proxy_cert.pem",
        )

        log.info(f"\n{'='*60}")
        log.info(f"PKI HIERARCHY GENERATED SUCCESSFULLY")
        log.info(f"{'='*60}")
        log.info(f"  Output directory : {cert_dir}")
        log.info(f"  Root CA          : ca_cert.pem / ca_key.pem")
        log.info(f"  Server Cert      : server_cert.pem / server_key.pem")
        log.info(f"  Client Cert      : client_cert.pem / client_key.pem")
        log.info(f"  Proxy Cert       : proxy_cert.pem / proxy_key.pem")
        log.info(f"{'='*60}")

        return cert_dir


# --- CLI Entry Point ---
if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Generate TLS/mTLS certificates for SecureLAN Communication Suite"
    )
    parser.add_argument(
        "--cert-dir", default=DEFAULT_CERT_DIR,
        help=f"Output directory for certificates (default: {DEFAULT_CERT_DIR})"
    )
    parser.add_argument(
        "--server-ip", default="127.0.0.1",
        help="Server LAN IP to include as a SAN (default: 127.0.0.1)"
    )

    args = parser.parse_args()
    CertificateGenerator.generate_all(args.cert_dir, args.server_ip)
