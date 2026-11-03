import io

import pytest
from rich.console import Console

from pemrescue import der
from pemrescue.analyze import analyze_bytes
from pemrescue.cli import main
from pemrescue.der import Status
from pemrescue.render import Options, render_all

EXPECTED_TYPE = {
    "cert": "cert", "rsa-private": "rsa-private", "rsa-public": "rsa-public",
    "ec-private": "ec-private", "dsa-private": "dsa-private", "pkcs8": "pkcs8",
    "pkcs8-ec": "pkcs8", "pkcs8-ed": "pkcs8", "pkcs8-dsa": "pkcs8",
    "pkcs8-encrypted": "pkcs8-encrypted", "spki": "spki", "spki-ec": "spki", "spki-ed": "spki",
}


def render(items) -> str:
    buf = io.StringIO()
    render_all(Console(file=buf, width=120, no_color=True), items, Options(), "t")
    return buf.getvalue()


def find(item, name):
    for top in item.nodes:
        for n in top.iter_all():
            if n.name == name:
                return n
    raise KeyError(name)


@pytest.mark.parametrize("key", list(EXPECTED_TYPE))
def test_intact_der_detected_and_clean(der_samples, key):
    (item,) = analyze_bytes(der_samples[key])
    assert item.type_key == EXPECTED_TYPE[key]
    assert not item.damaged
    assert item.stats.missing == 0 and item.stats.truncated == 0
    assert not any(n.notes for n in item.main.iter_all() if "额外" in "".join(n.notes))
    render([item])


@pytest.mark.parametrize("key", list(EXPECTED_TYPE))
def test_all_truncations(der_samples, key):
    data = der_samples[key]
    step = max(1, len(data) // 150)
    for cut in range(1, len(data), step):
        items = analyze_bytes(data[:cut], force_type=None)
        assert items and all(it.damaged for it in items), cut
        out = render(items)
        assert "截断" in out or "缺失" in out
        # 截断时语义类型仍应与标签给定的一致
        pem_items = analyze_bytes(data[:cut], force_type=EXPECTED_TYPE[key])
        render(pem_items)


def test_cert_cut_after_subject(der_samples):
    data = der_samples["cert"]
    (full,) = analyze_bytes(data)
    subj = find(full, "subject")
    (item,) = analyze_bytes(data[: subj.end + 3])
    assert find(item, "issuer").status is Status.COMPLETE
    s = find(item, "subject")
    assert s.status is Status.COMPLETE and not s.damaged
    assert s.spec.summary(s).startswith("C=CN, CN=test.example")
    assert find(item, "subjectPublicKeyInfo").status is not Status.COMPLETE
    assert find(item, "signatureValue").status is Status.MISSING


def test_rsa_cut_inside_p(der_samples):
    data = der_samples["rsa-private"]
    (full,) = analyze_bytes(data)
    p = find(full, "prime1 (p)")
    (item,) = analyze_bytes(data[: p.content_offset + 10])
    for name in ("modulus (n)", "publicExponent (e)", "privateExponent (d)"):
        assert find(item, name).status is Status.COMPLETE
    tp = find(item, "prime1 (p)")
    assert tp.status is Status.TRUNCATED and tp.content == p.content[:10]
    for name in ("prime2 (q)", "coefficient (qInv)"):
        n = find(item, name)
        assert n.status is Status.MISSING and not n.optional_missing


def test_pkcs8_encapsulated_cut(der_samples):
    data = der_samples["pkcs8"]
    (item,) = analyze_bytes(data[: len(data) // 2])
    assert find(item, "RSAPrivateKey").status is Status.TRUNCATED
    assert find(item, "modulus (n)").status is Status.COMPLETE


def test_pem_cert_truncated_mid_base64(cert):
    from cryptography.hazmat.primitives.serialization import Encoding

    text = cert.public_bytes(Encoding.PEM).decode()
    cut = text[: len(text) // 2 + 1]
    (item,) = analyze_bytes(cut.encode())
    assert item.type_key == "cert" and item.damaged and item.block.encoding_damaged
    have, total = item.completeness()
    assert total == len(cert.public_bytes(Encoding.DER)) and 0 < have < total


def test_concatenated_der(der_samples):
    data = der_samples["cert"] + der_samples["spki"]
    items = analyze_bytes(data)
    assert [i.type_key for i in items] == ["cert", "spki"]
    assert items[1].main.offset == len(der_samples["cert"])


def test_generic_mode(der_samples):
    (item,) = analyze_bytes(der_samples["cert"], semantic=False)
    assert item.type_key is None and item.main.name is None


def test_cli_exit_codes(tmp_path, der_samples, capsys):
    good = tmp_path / "good.der"
    bad = tmp_path / "bad.der"
    good.write_bytes(der_samples["cert"])
    bad.write_bytes(der_samples["cert"][:100])
    assert main([str(good), "--no-color"]) == 0
    assert main([str(bad), "--no-color"]) == 1
    assert main([str(tmp_path / "nope"), "--no-color"]) == 2
    out = capsys.readouterr().out
    assert "X.509 证书" in out


def test_malformed_never_crashes():
    import random

    rnd = random.Random(1)
    for _ in range(300):
        blob = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 80)))
        render(analyze_bytes(b"\x30" + blob))
    assert der.parse(b"") == []


def test_value_dump_copyable_hex(der_samples):
    data = der_samples["rsa-private"]
    (full,) = analyze_bytes(data)
    p = find(full, "prime1 (p)")
    out = render(analyze_bytes(data[: p.content_offset + 10]))
    dump = out[out.index("字段值"):]
    n = find(full, "modulus (n)")
    assert n.content.lstrip(b"\x00").hex() in dump.splitlines()  # 完整值独占一行
    assert p.content[1:10].hex() in dump.splitlines()            # 部分值同样输出
    assert f"⚠ 9/{len(p.content) - 1} 字节" in dump and "缺失：prime2 (q)" in dump


def test_value_dump_constructed_is_der(der_samples):
    data = der_samples["cert"]
    out = render(analyze_bytes(data))
    (item,) = analyze_bytes(data)
    issuer = find(item, "issuer")
    assert item.tlv_bytes(issuer).hex() in out.splitlines()


def test_cli_options(tmp_path, der_samples, capsys):
    f = tmp_path / "k.der"
    f.write_bytes(der_samples["spki"])
    assert main([str(f), "--no-color"]) == 0
    import re
    assert re.search(r"\s+\d+: ([0-9a-f]{2} ){3}", capsys.readouterr().out)  # 树中 hex 为带偏移的 hexdump
    assert main([str(f), "--no-summary", "--no-color"]) == 0
    assert "字段值" not in capsys.readouterr().out.split("k.der")[-1]
    for gone in ("--full", "--hexdump"):
        with pytest.raises(SystemExit):
            main([str(f), gone])
