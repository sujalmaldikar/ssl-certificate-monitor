
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# Output directory
output_dir = Path("test-certs")
output_dir.mkdir(exist_ok=True)

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Certificate identity
subject = issuer = x509.Name([
    x509.NameAttribute(
        NameOID.COMMON_NAME,
        "expired.example.com"
    )
])

# Set certificate validity in the past
now = datetime.now(timezone.utc)

certificate = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(days=10))
    .not_valid_after(now - timedelta(days=1))
    .sign(private_key, hashes.SHA256())
)

# Save certificate
cert_path = output_dir / "expired_test.crt"

cert_path.write_bytes(
    certificate.public_bytes(serialization.Encoding.PEM)
)

# Save private key
key_path = output_dir / "expired_test.key"

key_path.write_bytes(
    private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
)

print("Expired test certificate generated successfully!")
print(f"Certificate: {cert_path}")
print(f"Private key: {key_path}")

