"""输入层：识别 PEM / DER / 裸 Base64，并以容错方式解码 PEM 块。"""

from __future__ import annotations

import base64
import re
import string
from dataclasses import dataclass, field

B64_CHARS = set(string.ascii_letters + string.digits + "+/")
B64_TEXT_CHARS = B64_CHARS | set("=\r\n\t ")

BEGIN_RE = re.compile(r"^-----BEGIN ([^-]*)(-*)\s*$")
END_RE = re.compile(r"^-----END ([^-]*)-----\s*$")


@dataclass
class Block:
    kind: str  # "pem" | "der" | "base64"
    data: bytes
    label: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    line_start: int | None = None  # 1 起始
    line_end: int | None = None
    notes: list[str] = field(default_factory=list)  # 编码层的损坏说明
    encoding_damaged: bool = False

    @property
    def encrypted_legacy(self) -> bool:
        return "ENCRYPTED" in self.headers.get("Proc-Type", "").upper()

    def describe_source(self) -> str:
        if self.kind == "pem":
            lines = f"第 {self.line_start}–{self.line_end} 行" if self.line_end else f"第 {self.line_start} 行起"
            return f"PEM 块 “{self.label}”（{lines}）"
        if self.kind == "base64":
            return "裸 Base64 文本"
        return "DER 二进制"


def b64_tolerant(text: str) -> tuple[bytes, list[str], bool]:
    """宽松 Base64 解码。返回 (数据, 说明, 是否发现损坏)。"""
    notes: list[str] = []
    damaged = False
    bad = sum(1 for c in text if c not in B64_CHARS and c not in "=\r\n\t ")
    if bad:
        notes.append(f"忽略了 {bad} 个非 Base64 字符")
        damaged = True
    raw = "".join(c for c in text if c in B64_CHARS or c == "=")
    core = raw.rstrip("=")
    if "=" in core:
        notes.append("Base64 中间出现填充符 '='，已忽略")
        damaged = True
        core = core.replace("=", "")
    if len(raw) % 4 != 0 or len(raw) - len(core) > 2:
        rem = len(core) % 4
        if rem == 1:
            notes.append("Base64 末尾多余 1 个字符，已丢弃")
            core = core[:-1]
            damaged = True
        elif rem in (2, 3):
            notes.append("Base64 末尾分组不完整")
            damaged = True
    if len(core) % 4 == 1:
        core = core[:-1]
    pad = "=" * (-len(core) % 4)
    try:
        data = base64.b64decode(core + pad)
    except Exception:  # pragma: no cover - 理论上不会发生
        data = b""
        notes.append("Base64 解码失败")
        damaged = True
    return data, notes, damaged


def _is_text(raw: bytes) -> bool:
    try:
        raw.decode("ascii")
    except UnicodeDecodeError:
        return False
    return True


def extract_blocks(raw: bytes) -> list[Block]:
    if b"-----BEGIN" in raw:
        return _extract_pem(raw.decode("latin-1"))
    if raw and _is_text(raw):
        txt = raw.decode("ascii")
        if all(c in B64_TEXT_CHARS for c in txt) and len(txt.strip()) >= 8:
            data, notes, dmg = b64_tolerant(txt)
            return [Block("base64", data, notes=notes, encoding_damaged=dmg)]
    return [Block("der", raw)]


def _extract_pem(text: str) -> list[Block]:
    lines = text.splitlines()
    blocks: list[Block] = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i].strip()
        m = BEGIN_RE.match(line) if line.startswith("-----BEGIN") else None
        if not m:
            i += 1
            continue
        label = m.group(1).strip()
        blk = Block("pem", b"", label=label, line_start=i + 1)
        if m.group(2) != "-----":
            blk.notes.append("BEGIN 行不完整")
            blk.encoding_damaged = True
        i += 1
        # RFC 1421 头部
        body: list[str] = []
        in_headers = True
        last_key = None
        end_found = False
        while i < n:
            raw_line = lines[i]
            s = raw_line.strip()
            if s.startswith("-----BEGIN"):
                blk.notes.append("缺少 END 行")
                blk.encoding_damaged = True
                break
            if s.startswith("-"):
                em = END_RE.match(s)
                if em:
                    end_found = True
                    if em.group(1).strip() != label:
                        blk.notes.append("END 与 BEGIN 标签不一致")
                else:
                    blk.notes.append("END 行不完整")
                    blk.encoding_damaged = True
                    end_found = True
                blk.line_end = i + 1
                i += 1
                break
            if in_headers:
                if ":" in s and not body:
                    k, _, v = s.partition(":")
                    last_key = k.strip()
                    blk.headers[last_key] = v.strip()
                    i += 1
                    continue
                if last_key and raw_line[:1] in (" ", "\t") and not body:
                    blk.headers[last_key] += s
                    i += 1
                    continue
                if s == "" and blk.headers and not body:
                    in_headers = False
                    i += 1
                    continue
                in_headers = False
            body.append(s)
            i += 1
        else:
            if not end_found:
                blk.notes.append("缺少 END 行")
                blk.encoding_damaged = True
        if not end_found and blk.line_end is None:
            blk.line_end = i
        data, notes, dmg = b64_tolerant("".join(body))
        blk.data = data
        blk.notes.extend(notes)
        blk.encoding_damaged |= dmg
        blocks.append(blk)
    return blocks
