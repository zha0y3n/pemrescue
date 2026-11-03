"""把原始类型的内容字节转成人类可读的文本（支持部分数据）。"""

from __future__ import annotations

import ipaddress
import re

from . import der
from .der import CLS_CONTEXT, CLS_UNIVERSAL, Node, Status
from .oids import oid_name

UNIVERSAL_NAMES = {
    0: "EOC",
    1: "BOOLEAN",
    2: "INTEGER",
    3: "BIT STRING",
    4: "OCTET STRING",
    5: "NULL",
    6: "OBJECT IDENTIFIER",
    7: "ObjectDescriptor",
    8: "EXTERNAL",
    9: "REAL",
    10: "ENUMERATED",
    12: "UTF8String",
    13: "RELATIVE-OID",
    16: "SEQUENCE",
    17: "SET",
    18: "NumericString",
    19: "PrintableString",
    20: "T61String",
    21: "VideotexString",
    22: "IA5String",
    23: "UTCTime",
    24: "GeneralizedTime",
    25: "GraphicString",
    26: "VisibleString",
    27: "GeneralString",
    28: "UniversalString",
    30: "BMPString",
}

STRING_TAGS = {12, 18, 19, 20, 21, 22, 25, 26, 27, 28, 30}


def tag_name(node: Node) -> str:
    if node.status is Status.MALFORMED:
        return "<无法解析的字节>"
    if node.cls is None:
        return "<加密数据>"
    if node.tag is None:
        return "<标签不完整>"
    if node.cls == CLS_UNIVERSAL:
        return UNIVERSAL_NAMES.get(node.tag, f"UNIVERSAL {node.tag}")
    prefix = {1: "APPLICATION ", 2: "", 3: "PRIVATE "}[node.cls]
    return f"[{prefix}{node.tag}]"


# ---------------------------------------------------------------- OID


def decode_oid(b: bytes) -> tuple[str, bool]:
    """返回 (点分 OID, 是否完整)。最后一个 arc 不完整时以 '?' 表示。"""
    arcs: list[int] = []
    val = 0
    pending = False
    for byte in b:
        val = (val << 7) | (byte & 0x7F)
        pending = True
        if not byte & 0x80:
            arcs.append(val)
            val = 0
            pending = False
    if not arcs:
        return ("?" if b else ""), not pending
    first = arcs[0]
    if first < 40:
        head = [0, first]
    elif first < 80:
        head = [1, first - 40]
    else:
        head = [2, first - 80]
    s = ".".join(str(a) for a in head + arcs[1:])
    if pending:
        s += ".?"
    return s, not pending


def oid_of(node: Node | None) -> str | None:
    if node is None or not node.is_universal(der.OID) or node.status is not Status.COMPLETE:
        return None
    s, ok = decode_oid(node.content)
    return s if ok else None


def describe_oid(node: Node) -> str:
    s, ok = decode_oid(node.content)
    name = oid_name(s) if ok else None
    if not ok or node.status is not Status.COMPLETE:
        return f"{s}  (OID 不完整)"
    return f"{s} ({name})" if name else s


# ---------------------------------------------------------------- 整数


def int_value(node: Node | None) -> int | None:
    if node is None or node.status is not Status.COMPLETE or not node.content:
        return None
    return int.from_bytes(node.content, "big", signed=True)


def describe_integer(node: Node) -> str:
    b = node.content
    if node.status is not Status.COMPLETE:
        return None
    if not b:
        return "(空)"
    v = int.from_bytes(b, "big", signed=True)
    if len(b) <= 8:
        return f"{v} (0x{b.hex()})"
    return f"{v.bit_length()} bit 整数"


def _approx_bits(node: Node) -> int:
    n = node.length or 0
    if node.content[:1] == b"\x00":
        n -= 1
    return n * 8


# ---------------------------------------------------------------- 时间

_TIME_RE = re.compile(r"^(\d{2,4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(\.\d+)?(Z|[+-]\d{4})?$")


def describe_time(node: Node) -> str:
    raw = node.content.decode("ascii", "replace")
    if node.status is not Status.COMPLETE:
        return f'"{raw}…"'
    s = raw
    if node.tag == der.UTC_TIME:
        m = re.match(r"^(\d{2})(.*)$", s)
        if m:
            yy = int(m.group(1))
            s = f"{2000 + yy if yy < 50 else 1900 + yy}{m.group(2)}"
    m = _TIME_RE.match(s)
    if not m:
        return f'"{raw}"（格式无法识别）'
    year, mon, day, hh, mm, ss, frac, tz = m.groups()
    tz = tz or ""
    tzs = "UTC" if tz == "Z" else (f"UTC{tz[:3]}:{tz[3:]}" if tz else "本地时间")
    return f"{year}-{mon}-{day} {hh}:{mm}:{ss or '00'}{frac or ''} {tzs}"


# ---------------------------------------------------------------- 字符串


def decode_string(node: Node) -> str:
    b = node.content
    if node.tag == der.BMP_STRING:
        return b[: len(b) // 2 * 2].decode("utf-16-be", "replace")
    if node.tag == der.UNIVERSAL_STRING:
        return b[: len(b) // 4 * 4].decode("utf-32-be", "replace")
    if node.tag == der.UTF8_STRING:
        return b.decode("utf-8", "replace")
    return b.decode("latin-1")


def describe_string(node: Node) -> str:
    s = decode_string(node)
    if node.status is not Status.COMPLETE:
        return f'"{s}…"'
    return f'"{s}"'


def printable(b: bytes) -> bool:
    return bool(b) and all(32 <= c < 127 for c in b)


# ---------------------------------------------------------------- 入口


def describe(node: Node) -> str | None:
    """通用的值描述；构造型节点返回 None。"""
    if node.constructed or node.status in (Status.MALFORMED, Status.MISSING):
        return None
    if node.status is Status.HEADER_TRUNCATED:
        return None
    if node.cls == CLS_UNIVERSAL:
        t = node.tag
        if t == der.BOOLEAN:
            if not node.content:
                return "值缺失"
            return "TRUE" if node.content[0] else "FALSE"
        if t in (der.INTEGER, 10):
            return describe_integer(node)
        if t == der.NULL:
            return None
        if t == der.OID:
            return describe_oid(node)
        if t in (der.UTC_TIME, der.GENERALIZED_TIME):
            return describe_time(node)
        if t in STRING_TAGS:
            return describe_string(node)
        if t == der.BIT_STRING:
            if not node.content:
                return "值缺失"
            n = len(node.content) - 1
            if node.status is Status.COMPLETE:
                return f"未使用位 {node.content[0]}，{n} 字节"
            return None
        if t == der.OCTET_STRING:
            if node.status is Status.COMPLETE:
                txt = f'  "{node.content.decode()}"' if printable(node.content) else ""
                return f"{len(node.content)} 字节{txt}"
            return None
    if node.cls == CLS_CONTEXT and printable(node.content):
        return f'"{node.content.decode()}"'
    return None


# ---------------------------------------------------------------- 专用渲染器


def render_version(node: Node) -> str | None:
    v = int_value(node)
    if v is None:
        return describe_integer(node)
    return f"{v} (v{v + 1})"


KEY_USAGE_BITS = [
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
]


def render_key_usage(node: Node) -> str | None:
    if len(node.content) < 1:
        return describe(node)
    bits = node.content[1:]
    flags = []
    for i, name in enumerate(KEY_USAGE_BITS):
        byte, bit = divmod(i, 8)
        if byte < len(bits) and bits[byte] & (0x80 >> bit):
            flags.append(name)
    s = ", ".join(flags) or "(无)"
    return s if node.status is Status.COMPLETE else s + "…"


GENERAL_NAME_TAGS = {
    0: "otherName",
    1: "rfc822Name",
    2: "dNSName",
    3: "x400Address",
    4: "directoryName",
    5: "ediPartyName",
    6: "uniformResourceIdentifier",
    7: "iPAddress",
    8: "registeredID",
}


def render_general_name(node: Node) -> str | None:
    if node.cls != CLS_CONTEXT or node.tag is None:
        return describe(node)
    kind = GENERAL_NAME_TAGS.get(node.tag, f"[{node.tag}]")
    b = node.content
    trunc = "" if node.status is Status.COMPLETE else "…"
    if node.tag in (1, 2, 6):
        return f'{kind} = "{b.decode("latin-1")}"{trunc}'
    if node.tag == 7:
        if node.status is Status.COMPLETE and len(b) in (4, 16):
            return f"{kind} = {ipaddress.ip_address(b)}"
        if node.status is Status.COMPLETE and len(b) in (8, 32):
            half = len(b) // 2
            return f"{kind} = {ipaddress.ip_address(b[:half])}/{ipaddress.ip_address(b[half:])}"
        return f"{kind} = {b.hex()}{trunc}"
    if node.tag == 8:
        return f"{kind} = {decode_oid(b)[0]}{trunc}"
    return kind


def render_ec_point(node: Node) -> str | None:
    """BIT STRING 或 OCTET STRING 中的 SEC1 椭圆曲线点。"""
    b = node.content
    if node.is_universal(der.BIT_STRING) or (node.cls == CLS_CONTEXT and node.tag == 1 and not node.constructed):
        b = b[1:]
    if not b:
        return describe(node)
    fmt = {2: "压缩点 (y 偶)", 3: "压缩点 (y 奇)", 4: "未压缩点 04||x||y"}.get(b[0], f"未知格式 0x{b[0]:02x}")
    s = f"EC 公钥点：{fmt}"
    if b[0] == 4 and node.status is Status.COMPLETE and len(b) % 2 == 1:
        size = (len(b) - 1) // 2
        s += f"，坐标 {size * 8} bit"
    return s


def render_raw_key(label: str):
    def _r(node: Node) -> str | None:
        b = node.content
        if node.is_universal(der.BIT_STRING):
            b = b[1:]
        if node.status is not Status.COMPLETE:
            return label
        return f"{label}，{len(b)} 字节"

    return _r


def render_ec_scalar(node: Node) -> str | None:
    n = len(node.content)
    if node.status is not Status.COMPLETE:
        return "EC 私钥标量"
    return f"EC 私钥标量，{n * 8} bit"
