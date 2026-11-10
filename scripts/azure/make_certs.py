"""Create a private CA and a server certificate for the Flower SuperLink and the endpoint.

    python scripts/azure/make_certs.py --out D:/federated-ids-work/azure/tls

The server certificate is valid for the server VM's private IP (clients on the Azure client VM
connect to it) and for 127.0.0.1/localhost (the laptop connects through SSH tunnels). Private
keys stay outside the repository. Validity: 90 days. Subject/Authority Key Identifiers are
included because strict X.509 verification (Python >= 3.13, browsers) rejects certificates without them.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _write(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--server-ip", default="10.20.1.4")
    ap.add_argument("--days", type=int, default=90)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fids private CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now).not_valid_after(now + dt.timedelta(days=a.days))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                       content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False,
                                       encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))

    key = ec.generate_private_key(ec.SECP256R1())
    san = x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName("fids-server"),
                                       x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                                       x509.IPAddress(ipaddress.ip_address(a.server_ip))])
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fids-server")]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=a.days))
            .add_extension(san, critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))

    pem = serialization.Encoding.PEM
    nopw = serialization.NoEncryption()
    _write(out / "ca.crt", ca.public_bytes(pem))
    _write(out / "ca.key", ca_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, nopw))
    _write(out / "server.pem", cert.public_bytes(pem))
    _write(out / "server.key", key.private_bytes(pem, serialization.PrivateFormat.PKCS8, nopw))
    print(f"wrote ca.crt, ca.key, server.pem, server.key to {out} (SAN: localhost, 127.0.0.1, {a.server_ip})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
