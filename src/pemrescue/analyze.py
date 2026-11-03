"""把输入块解析成带语义的对象，并统计完整度。"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import der
from . import schema as SC
from . import values as V
from .der import Node, Status
from .pem import Block, extract_blocks

# 类型键 -> (中文名, 结构)
TYPES: dict[str, tuple[str, SC.F]] = {
    "cert": ("X.509 证书", SC.Certificate),
    "rsa-private": ("RSA 私钥 (PKCS#1)", SC.RSAPrivateKey),
    "rsa-public": ("RSA 公钥 (PKCS#1)", SC.RSAPublicKey),
    "ec-private": ("EC 私钥 (SEC1)", SC.ECPrivateKey),
    "dsa-private": ("DSA 私钥 (OpenSSL 传统格式)", SC.DSAPrivateKeyTraditional),
    "pkcs8": ("私钥 (PKCS#8)", SC.PrivateKeyInfo),
    "pkcs8-encrypted": ("加密私钥 (PKCS#8 EncryptedPrivateKeyInfo)", SC.EncryptedPrivateKeyInfo),
    "spki": ("公钥 (SubjectPublicKeyInfo)", SC.SubjectPublicKeyInfo),
    "ec-params": ("EC 参数", SC.ECParameters),
}

PEM_LABELS = {
    "CERTIFICATE": "cert",
    "X509 CERTIFICATE": "cert",
    "TRUSTED CERTIFICATE": "cert",
    "RSA PRIVATE KEY": "rsa-private",
    "RSA PUBLIC KEY": "rsa-public",
    "EC PRIVATE KEY": "ec-private",
    "DSA PRIVATE KEY": "dsa-private",
    "PRIVATE KEY": "pkcs8",
    "ENCRYPTED PRIVATE KEY": "pkcs8-encrypted",
    "PUBLIC KEY": "spki",
    "EC PARAMETERS": "ec-params",
}


def _label_type(label: str | None) -> str | None:
    if not label:
        return None
    label = label.strip().upper()
    if label in PEM_LABELS:
        return PEM_LABELS[label]
    # BEGIN 行被截断时按前缀匹配
    cands = [v for k, v in PEM_LABELS.items() if k.startswith(label)]
    return cands[0] if len(set(cands)) == 1 else None


def _u(node: Node | None, tag: int) -> bool:
    return node is not None and node.is_universal(tag)


def detect(node: Node) -> str | None:
    """仅凭结构猜测类型（适用于 DER 或标签未知的 PEM）。数据不完整时尽力而为。"""
    if not _u(node, der.SEQUENCE) and not (node.status is Status.HEADER_TRUNCATED and node.tag == der.SEQUENCE):
        return None
    k = node.children
    k0 = k[0] if k else None
    k1 = k[1] if len(k) > 1 else None
    k2 = k[2] if len(k) > 2 else None

    # 证书：SEQUENCE { SEQUENCE { [0]? INTEGER AlgId ... } ...}
    if _u(k0, der.SEQUENCE):
        g = k0.children
        if g and (g[0].cls == der.CLS_CONTEXT and g[0].tag == 0 or _u(g[0], der.INTEGER)):
            return "cert"
        if g and _u(g[0], der.OID):
            # AlgorithmIdentifier 开头：SPKI 或加密 PKCS#8
            if k1 is None:
                oid = V.oid_of(g[0])
                if oid and (oid in SC.PKCS12_PBE or oid in SC.PBES1 or oid.startswith("1.2.840.113549.1.5")):
                    return "pkcs8-encrypted"
                return "spki"
            if _u(k1, der.BIT_STRING):
                return "spki"
            if _u(k1, der.OCTET_STRING):
                return "pkcs8-encrypted"
        if g and g[0].status is Status.HEADER_TRUNCATED:
            return "cert"

    if _u(k0, der.INTEGER):
        ver = V.int_value(k0)
        if _u(k1, der.SEQUENCE):
            return "pkcs8"
        if _u(k1, der.OCTET_STRING) and ver == 1:
            return "ec-private"
        if ver == 0 and _u(k1, der.INTEGER):
            ints = [c for c in k if _u(c, der.INTEGER)]
            if len(ints) >= 7:
                return "rsa-private"
            if len(ints) == 6 and all(c.status is Status.COMPLETE for c in ints):
                return "dsa-private"
            if k2 is not None and _u(k2, der.INTEGER):
                # RSA 的第 3 个整数是 e（通常很小）；DSA 的是 q（160/224/256 bit）
                return "rsa-private" if (k2.length or 0) <= 4 else "dsa-private"
            return "rsa-private"
        if ver is not None and ver != 0 and _u(k1, der.INTEGER):
            return "rsa-public"
        if k1 is None and (k0.length or 0) > 8:
            return "rsa-public"
    return None


@dataclass
class Stats:
    complete_leaves: int = 0
    truncated: int = 0
    missing: int = 0
    missing_optional: int = 0


@dataclass
class Item:
    block: Block
    nodes: list[Node]
    type_key: str | None
    type_reason: str
    base: int = 0  # block.data[0] 在节点偏移中的位置
    stats: Stats = field(default_factory=Stats)

    @property
    def type_name(self) -> str:
        if self.block.encrypted_legacy:
            return f"传统 PEM 加密的 {self.block.label}"
        if self.type_key:
            return TYPES[self.type_key][0]
        return "未知结构（通用 ASN.1）"

    @property
    def main(self) -> Node | None:
        return self.nodes[0] if self.nodes else None

    @property
    def damaged(self) -> bool:
        return self.block.encoding_damaged or any(n.damaged for n in self.nodes)

    def tlv_bytes(self, n: Node) -> bytes:
        """节点在原始数据中的完整编码（标签 + 长度 + 已有内容）。"""
        a = n.offset - self.base
        return self.block.data[a : a + n.header_len + len(n.content)]

    def completeness(self) -> tuple[int, int | None]:
        """(可用字节, 声明的总字节)。"""
        m = self.main
        if m is None:
            return 0, None
        have = len(self.block.data)
        total = m.declared_total
        if total is None:
            return have, None
        return min(have, total), total


def _collect_stats(nodes: list[Node]) -> Stats:
    st = Stats()
    for top in nodes:
        for n in top.iter_all():
            if n.status is Status.MISSING:
                if n.optional_missing:
                    st.missing_optional += 1
                else:
                    st.missing += 1
            elif n.status is not Status.COMPLETE:
                if not n.constructed or not n.children:
                    st.truncated += 1
            elif not n.constructed:
                st.complete_leaves += 1
    return st


def analyze_block(block: Block, force_type: str | None = None, semantic: bool = True, base: int = 0) -> Item:
    if block.encrypted_legacy:
        # 传统 PEM 加密：正文是密文，不是 DER
        n = Node(offset=0, cls=None, content=block.data, status=Status.COMPLETE, name="密文",
                 spec=SC.F("密文", report=True))
        n.length = len(block.data)
        dek = block.headers.get("DEK-Info", "")
        if dek:
            cipher, _, iv = dek.partition(",")
            n.notes.append(cipher.strip())
            if iv:
                n.notes.append(f"IV {iv.strip().lower()}")
        return Item(block, [n], None, "PEM 头部 Proc-Type: ENCRYPTED")

    nodes = der.parse(block.data, base, eof=True)
    type_key = None
    reason = ""
    if semantic and nodes:
        if force_type:
            type_key, reason = force_type, "命令行指定"
        else:
            lt = _label_type(block.label)
            if lt:
                type_key, reason = lt, f"PEM 标签 “{block.label}”"
            else:
                type_key = detect(nodes[0])
                reason = "结构特征推断" if type_key else "无法识别"
        if type_key:
            SC.apply(nodes[0], TYPES[type_key][1])
        else:
            SC.generic(nodes[0])
        rest = nodes[1:]
        for extra in rest:
            sub = detect(extra)
            if sub and block.label == "TRUSTED CERTIFICATE":
                sub = None
            if sub:
                SC.apply(extra, TYPES[sub][1])
                extra.notes.append(TYPES[sub][0])
            else:
                SC.generic(extra)
                extra.notes.append("附加数据")
    else:
        for n in nodes:
            SC.generic(n)
        reason = "通用模式" if nodes else "无数据"
    item = Item(block, nodes, type_key, reason, base)
    item.stats = _collect_stats(nodes)
    return item


def analyze_bytes(raw: bytes, force_type: str | None = None, semantic: bool = True) -> list[Item]:
    blocks = extract_blocks(raw)
    items: list[Item] = []
    for b in blocks:
        if b.kind == "der" and not force_type:
            # DER 文件中可能直接拼接了多个对象：逐个拆分
            nodes = der.parse(b.data, 0, eof=True)
            if len(nodes) > 1 and all(n.is_universal(der.SEQUENCE) for n in nodes if n.status is Status.COMPLETE):
                for n in nodes:
                    sub = Block("der", b.data[n.offset : n.offset + len(n.content) + n.header_len])
                    sub.notes = [f"DER 文件中偏移 {n.offset} 处的对象"]
                    items.append(analyze_block(sub, None, semantic, base=n.offset))
                continue
        items.append(analyze_block(b, force_type, semantic))
    return items

