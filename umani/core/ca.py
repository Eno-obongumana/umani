from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


CA_DIR = Path(__file__).parent.parent / "ca"
CA_CERT = CA_DIR / "umani-ca.pem"
CA_KEY = CA_DIR / "umani-ca.key"
HOSTS_DIR = CA_DIR / "hosts"


class CA:
    def __init__(self):
        CA_DIR.mkdir(parents=True, exist_ok=True)
        HOSTS_DIR.mkdir(parents=True, exist_ok=True)
        if CA_CERT.exists() and CA_KEY.exists():
            self.cert = x509.load_pem_x509_certificate(CA_CERT.read_bytes())
            self.key = serialization.load_pem_private_key(
                CA_KEY.read_bytes(), password=None)
        else:
            self._generate_root()

    def _generate_root(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "UMANI Local CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UMANI Testing"),
        ])
        now = datetime.now(timezone.utc)
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .sign(self.key, hashes.SHA256())
        )
        CA_CERT.write_bytes(self.cert.public_bytes(serialization.Encoding.PEM))
        CA_KEY.write_bytes(self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        print(f"[ca] generated root CA at {CA_CERT}")

    def leaf_for(self, hostname: str):
        safe = hostname.replace(":", "_").replace("*", "wildcard")
        cert_path = HOSTS_DIR / f"{safe}.pem"
        key_path = HOSTS_DIR / f"{safe}.key"
        if cert_path.exists() and key_path.exists():
            return cert_path, key_path

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                critical=False,
            )
            .sign(self.key, hashes.SHA256())
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        return cert_path, key_path
