import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.x509.oid import NameOID

DER = serialization.Encoding.DER
PEM = serialization.Encoding.PEM
NOENC = serialization.NoEncryption()
PKCS8 = serialization.PrivateFormat.PKCS8
TRAD = serialization.PrivateFormat.TraditionalOpenSSL
SPKI = serialization.PublicFormat.SubjectPublicKeyInfo


@pytest.fixture(scope="session")
def keys():
    return {
        "rsa": rsa.generate_private_key(65537, 1024),
        "ec": ec.generate_private_key(ec.SECP256R1()),
        "ed": ed25519.Ed25519PrivateKey.generate(),
        "dsa": dsa.generate_private_key(1024),
    }


@pytest.fixture(scope="session")
def cert(keys):
    k = keys["rsa"]
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example"),
    ])
    t = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(k.public_key())
        .serial_number(4242).not_valid_before(t).not_valid_after(t + dt.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("test.example")]), False)
        .sign(k, hashes.SHA256())
    )


@pytest.fixture(scope="session")
def der_samples(keys, cert):
    """类型键 -> DER 字节。"""
    enc = serialization.BestAvailableEncryption(b"pw")
    return {
        "cert": cert.public_bytes(DER),
        "rsa-private": keys["rsa"].private_bytes(DER, TRAD, NOENC),
        "rsa-public": keys["rsa"].public_key().public_bytes(DER, serialization.PublicFormat.PKCS1),
        "ec-private": keys["ec"].private_bytes(DER, TRAD, NOENC),
        "dsa-private": keys["dsa"].private_bytes(DER, TRAD, NOENC),
        "pkcs8": keys["rsa"].private_bytes(DER, PKCS8, NOENC),
        "pkcs8-ec": keys["ec"].private_bytes(DER, PKCS8, NOENC),
        "pkcs8-ed": keys["ed"].private_bytes(DER, PKCS8, NOENC),
        "pkcs8-dsa": keys["dsa"].private_bytes(DER, PKCS8, NOENC),
        "pkcs8-encrypted": keys["rsa"].private_bytes(DER, PKCS8, enc),
        "spki": keys["rsa"].public_key().public_bytes(DER, SPKI),
        "spki-ec": keys["ec"].public_key().public_bytes(DER, SPKI),
        "spki-ed": keys["ed"].public_key().public_bytes(DER, SPKI),
    }
