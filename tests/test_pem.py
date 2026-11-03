import base64

from pemrescue.pem import b64_tolerant, extract_blocks

BODY = base64.b64encode(bytes(range(60))).decode()
PEM = f"-----BEGIN CERTIFICATE-----\n{BODY[:64]}\n{BODY[64:]}\n-----END CERTIFICATE-----\n"


def test_b64_intact():
    data, notes, dmg = b64_tolerant(BODY)
    assert data == bytes(range(60)) and not notes and not dmg


def test_b64_partial_group():
    s = base64.b64encode(b"abcdef").decode()  # 8 个字符
    data, notes, dmg = b64_tolerant(s[:7])  # 3 个字符的残组 -> 2 字节
    assert data == b"abcde" and dmg
    data, notes, dmg = b64_tolerant(s[:5])  # 1 个字符无法成字节
    assert data == b"abc" and dmg and "多余 1 个字符" in notes[0]


def test_pem_intact():
    (b,) = extract_blocks(PEM.encode())
    assert b.label == "CERTIFICATE" and b.data == bytes(range(60))
    assert not b.notes and not b.encoding_damaged
    assert (b.line_start, b.line_end) == (1, 4)


def test_pem_missing_end():
    text = PEM.split("-----END")[0]
    (b,) = extract_blocks(text.encode())
    assert b.encoding_damaged and any("END" in n for n in b.notes)
    assert b.data == bytes(range(60))


def test_pem_half_end_line():
    text = PEM[: PEM.index("-----END") + 7]
    (b,) = extract_blocks(text.encode())
    assert b.encoding_damaged and b.data == bytes(range(60))
    assert any("END 行不完整" in n for n in b.notes)


def test_pem_multiple_blocks_and_garbage():
    text = "Bag Attributes\n  localKeyID: 01\n" + PEM + "junk\n" + PEM.replace("CERTIFICATE", "PRIVATE KEY")
    blocks = extract_blocks(text.encode())
    assert [b.label for b in blocks] == ["CERTIFICATE", "PRIVATE KEY"]


def test_pem_missing_end_followed_by_begin():
    text = PEM.split("-----END")[0] + PEM
    blocks = extract_blocks(text.encode())
    assert len(blocks) == 2 and blocks[0].encoding_damaged and not blocks[1].encoding_damaged


def test_pem_rfc1421_headers():
    text = ("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00FF\n\n"
            f"{BODY}\n-----END RSA PRIVATE KEY-----\n")
    (b,) = extract_blocks(text.encode())
    assert b.encrypted_legacy and b.headers["DEK-Info"] == "AES-128-CBC,00FF"
    assert b.data == bytes(range(60))


def test_der_and_bare_base64():
    (b,) = extract_blocks(b"\x30\x03\x02\x01\x05")
    assert b.kind == "der"
    (b,) = extract_blocks(BODY.encode() + b"\n")
    assert b.kind == "base64" and b.data == bytes(range(60))
