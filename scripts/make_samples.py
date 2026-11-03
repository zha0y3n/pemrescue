"""生成完整的证书 / 密钥样本，以及在不同位置截断的损坏版本。

用法：
    uv run --group dev scripts/make_samples.py [输出目录，默认 samples]

输出：
    <out>/intact/     完整文件
    <out>/truncated/  截断文件，文件名标明截断方式
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PEM = serialization.Encoding.PEM
DER = serialization.Encoding.DER
PKCS8 = serialization.PrivateFormat.PKCS8
TRAD = serialization.PrivateFormat.TraditionalOpenSSL
SPKI = serialization.PublicFormat.SubjectPublicKeyInfo
NOENC = serialization.NoEncryption()
PASSWORD = b"pemrescue"


def make_cert(key, issuer_key=None, cn="pemrescue.example", ca=False):
    issuer_key = issuer_key or key
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PemRescue 测试组织"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    now = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    b = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x1234_5678_9ABC_DEF0)
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, not ca, False, False, ca, ca, False, False), critical=True
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if not ca:
        b = b.add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(cn),
                    x509.DNSName("www." + cn),
                    x509.IPAddress(ipaddress.ip_address("192.0.2.10")),
                ]
            ),
            critical=False,
        ).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    algo = None if isinstance(issuer_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return b.sign(issuer_key, algo)


def intact_samples() -> dict[str, bytes]:
    rsa_key = rsa.generate_private_key(65537, 2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ed_key = ed25519.Ed25519PrivateKey.generate()
    x_key = x25519.X25519PrivateKey.generate()
    dsa_key = dsa.generate_private_key(2048)

    rsa_cert = make_cert(rsa_key)
    ec_cert = make_cert(ec_key, cn="ec.pemrescue.example")
    ed_cert = make_cert(ed_key, cn="ed25519.pemrescue.example")
    ca_cert = make_cert(rsa_key, cn="PemRescue Root CA", ca=True)

    s: dict[str, bytes] = {
        "rsa_cert.pem": rsa_cert.public_bytes(PEM),
        "rsa_cert.der": rsa_cert.public_bytes(DER),
        "ec_cert.pem": ec_cert.public_bytes(PEM),
        "ed25519_cert.pem": ed_cert.public_bytes(PEM),
        "chain.pem": rsa_cert.public_bytes(PEM) + ca_cert.public_bytes(PEM),
        "cert_and_key.pem": rsa_cert.public_bytes(PEM) + rsa_key.private_bytes(PEM, TRAD, NOENC),
        "rsa_pkcs1.pem": rsa_key.private_bytes(PEM, TRAD, NOENC),
        "rsa_pkcs1.der": rsa_key.private_bytes(DER, TRAD, NOENC),
        "rsa_pkcs8.pem": rsa_key.private_bytes(PEM, PKCS8, NOENC),
        "rsa_public_spki.pem": rsa_key.public_key().public_bytes(PEM, SPKI),
        "rsa_public_pkcs1.pem": rsa_key.public_key().public_bytes(PEM, serialization.PublicFormat.PKCS1),
        "ec_sec1.pem": ec_key.private_bytes(PEM, TRAD, NOENC),
        "ec_pkcs8.der": ec_key.private_bytes(DER, PKCS8, NOENC),
        "ec_public.pem": ec_key.public_key().public_bytes(PEM, SPKI),
        "ed25519_pkcs8.pem": ed_key.private_bytes(PEM, PKCS8, NOENC),
        "ed25519_public.pem": ed_key.public_key().public_bytes(PEM, SPKI),
        "x25519_pkcs8.pem": x_key.private_bytes(PEM, PKCS8, NOENC),
        "dsa_traditional.pem": dsa_key.private_bytes(PEM, TRAD, NOENC),
        "dsa_pkcs8.pem": dsa_key.private_bytes(PEM, PKCS8, NOENC),
        "dsa_public.pem": dsa_key.public_key().public_bytes(PEM, SPKI),
        "rsa_encrypted_pkcs8.pem": rsa_key.private_bytes(
            PEM, PKCS8, serialization.BestAvailableEncryption(PASSWORD)
        ),
        "rsa_encrypted_legacy.pem": rsa_key.private_bytes(
            PEM, TRAD, serialization.BestAvailableEncryption(PASSWORD)
        ),
    }
    return s


def truncations(name: str, data: bytes) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    stem, ext = name.rsplit(".", 1)
    if ext == "pem":
        text = data.decode()
        lines = text.splitlines(keepends=True)
        # 去掉 END 行
        no_end = "".join(l for l in lines if not l.startswith("-----END"))
        out[f"{stem}__no_end.{ext}"] = no_end.encode()
        # END 行只剩一半
        idx = text.rfind("-----END")
        out[f"{stem}__half_end.{ext}"] = text[: idx + 9].encode()
        # 在 Base64 正文中按比例截断，故意落在分组中间
        body_start = text.index("\n") + 1
        body_end = text.index("-----END")
        for pct in (25, 50, 75, 95):
            cut = body_start + (body_end - body_start) * pct // 100
            while text[cut] == "\n":
                cut += 1
            cut += 1  # 尽量让 Base64 分组不完整
            out[f"{stem}__cut{pct}.{ext}"] = text[:cut].encode()
    else:
        for pct in (10, 25, 50, 75, 95):
            out[f"{stem}__cut{pct}.{ext}"] = data[: len(data) * pct // 100]
        out[f"{stem}__minus1.{ext}"] = data[:-1]
    return out


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "samples")
    (out / "intact").mkdir(parents=True, exist_ok=True)
    (out / "truncated").mkdir(parents=True, exist_ok=True)
    samples = intact_samples()
    n = 0
    for name, data in samples.items():
        (out / "intact" / name).write_bytes(data)
        for tname, tdata in truncations(name, data).items():
            (out / "truncated" / tname).write_bytes(tdata)
            n += 1
    print(f"已生成 {len(samples)} 个完整样本、{n} 个截断样本 → {out}/")
    print(f"加密样本的口令：{PASSWORD.decode()}")


if __name__ == "__main__":
    main()
