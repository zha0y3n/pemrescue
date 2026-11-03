"""容错 DER/BER 解析器。

与常规解析器不同，这里遇到数据不足时不会抛异常，而是尽可能多地解析，
并在节点上标注损坏状态：

* COMPLETE          —— 标签、长度、内容全部完整
* TRUNCATED         —— 声明的长度超出了文件末尾，内容只拿到一部分
* HEADER_TRUNCATED  —— 连标签或长度字节都没读全
* OVERFLOW          —— 声明的长度超出了父结构的边界（非文件末尾）
* MALFORMED         —— 无法识别为 TLV 的残余字节
* MISSING           —— 由语义层插入的占位符：按结构应存在，但数据中没有
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

MAX_DEPTH = 64

CLS_UNIVERSAL = 0
CLS_APPLICATION = 1
CLS_CONTEXT = 2
CLS_PRIVATE = 3

# 常用通用标签号
BOOLEAN = 1
INTEGER = 2
BIT_STRING = 3
OCTET_STRING = 4
NULL = 5
OID = 6
UTF8_STRING = 12
SEQUENCE = 16
SET = 17
PRINTABLE_STRING = 19
T61_STRING = 20
IA5_STRING = 22
UTC_TIME = 23
GENERALIZED_TIME = 24
VISIBLE_STRING = 26
UNIVERSAL_STRING = 28
BMP_STRING = 30


class Status(Enum):
    COMPLETE = "complete"
    TRUNCATED = "truncated"
    HEADER_TRUNCATED = "header_truncated"
    OVERFLOW = "overflow"
    MALFORMED = "malformed"
    MISSING = "missing"


DAMAGED_AT_END = {Status.TRUNCATED, Status.HEADER_TRUNCATED, Status.OVERFLOW}


@dataclass(eq=False)
class Node:
    offset: int  # 绝对偏移；MISSING 节点为 -1
    cls: int | None = None
    constructed: bool = False
    tag: int | None = None
    header_len: int = 0
    length: int | None = None  # 声明长度；未知或不定长时为 None
    content: bytes = b""  # 实际可用的内容字节
    status: Status = Status.COMPLETE
    children: list[Node] = field(default_factory=list)
    indefinite: bool = False

    # ---- 语义层注解 ----
    name: str | None = None
    alias: str | None = None  # 动态解析出的具体类型名（如 parameters 实际是 iv）
    spec: object = None
    notes: list[str] = field(default_factory=list)
    encapsulated: list[Node] | None = None
    display: Callable[[Node], str | None] | None = None
    guessed: bool = False
    optional_missing: bool = False

    @property
    def content_offset(self) -> int:
        return self.offset + self.header_len

    @property
    def end(self) -> int:
        return self.content_offset + len(self.content)

    @property
    def declared_total(self) -> int | None:
        if self.length is None:
            return None
        return self.header_len + self.length

    @property
    def missing_bytes(self) -> int:
        if self.length is None:
            return 0
        return max(0, self.length - len(self.content))

    def is_universal(self, tag: int) -> bool:
        return self.cls == CLS_UNIVERSAL and self.tag == tag

    def iter_all(self):
        """深度优先遍历自身、子节点以及封装在 OCTET/BIT STRING 内的节点。"""
        yield self
        for c in self.children:
            yield from c.iter_all()
        for c in self.encapsulated or ():
            yield from c.iter_all()

    @property
    def damaged(self) -> bool:
        return any(n.status is not Status.COMPLETE for n in self.iter_all())

    def child(self, name: str) -> Node | None:
        for c in self.children:
            if c.name == name:
                return c
        for c in self.encapsulated or ():
            if c.name == name:
                return c
        return None


def parse(data: bytes, base: int = 0, eof: bool = True) -> list[Node]:
    """解析一段字节中的所有顶层 TLV。

    ``base`` 为 ``data[0]`` 在原始数据中的绝对偏移；``eof`` 表示 ``data`` 的末尾
    是否就是真实数据末尾（决定越界时标为 TRUNCATED 还是 OVERFLOW）。
    """
    nodes, _, _ = _parse_seq(data, 0, len(data), base, eof, 0, stop_at_eoc=False)
    return nodes


def _parse_seq(data, pos, end, base, eof, depth, stop_at_eoc):
    """返回 (nodes, 结束位置, 是否遇到 EOC)。"""
    nodes: list[Node] = []
    while pos < end:
        if stop_at_eoc and data[pos : pos + 2] == b"\x00\x00" and pos + 2 <= end:
            return nodes, pos + 2, True
        node = _parse_one(data, pos, end, base, eof, depth)
        nodes.append(node)
        if node.status is not Status.COMPLETE:
            # 截断/越界/格式错误的节点已经消耗到区域末尾
            return nodes, end, False
        pos = node.end - base
    return nodes, pos, False


def _malformed(data, pos, end, base, note) -> Node:
    n = Node(offset=base + pos, content=bytes(data[pos:end]), status=Status.MALFORMED)
    n.notes.append(note)
    return n


def _parse_one(data, pos, end, base, eof, depth) -> Node:
    start = pos
    b = data[pos]
    pos += 1
    cls = b >> 6
    constructed = bool(b & 0x20)
    tag: int | None = b & 0x1F
    cut_status = Status.HEADER_TRUNCATED if eof else Status.OVERFLOW

    if tag == 0x1F:  # 高标签号形式
        tag = 0
        for i in range(6):
            if pos >= end:
                return Node(base + start, cls, constructed, None, pos - start, status=cut_status)
            c = data[pos]
            pos += 1
            tag = (tag << 7) | (c & 0x7F)
            if not c & 0x80:
                break
        else:
            return _malformed(data, start, end, base, "标签字节过长，无法识别为 TLV")

    if pos >= end:
        return Node(base + start, cls, constructed, tag, pos - start, status=cut_status)

    lb = data[pos]
    pos += 1
    indefinite = False
    length: int | None
    if lb == 0x80:
        if not constructed:
            return _malformed(data, start, end, base, "原始类型不允许不定长编码")
        indefinite = True
        length = None
    elif lb & 0x80:
        nlen = lb & 0x7F
        if nlen > 8 or nlen == 0x7F:
            return _malformed(data, start, end, base, f"长度字段非法（{nlen} 字节长度）")
        if pos + nlen > end:
            return Node(base + start, cls, constructed, tag, end - start, status=cut_status)
        length = int.from_bytes(data[pos : pos + nlen], "big")
        pos += nlen
    else:
        length = lb

    node = Node(base + start, cls, constructed, tag, pos - start, length, indefinite=indefinite)
    cstart = pos

    if indefinite:
        if depth >= MAX_DEPTH:
            node.content = bytes(data[cstart:end])
            node.notes.append("嵌套过深，停止解析")
            return node
        kids, p2, terminated = _parse_seq(data, cstart, end, base, eof, depth + 1, stop_at_eoc=True)
        node.children = kids
        node.content = bytes(data[cstart:p2])
        if not terminated:
            node.status = Status.TRUNCATED if eof else Status.OVERFLOW
        return node

    avail = end - cstart
    if length > avail:
        node.status = Status.TRUNCATED if eof else Status.OVERFLOW
        node.content = bytes(data[cstart:end])
    else:
        node.content = bytes(data[cstart : cstart + length])

    if constructed and depth < MAX_DEPTH:
        child_eof = node.status is Status.TRUNCATED
        kids, _, _ = _parse_seq(
            data, cstart, cstart + len(node.content), base, child_eof, depth + 1, stop_at_eoc=False
        )
        node.children = kids
    return node


def try_parse_exact(data: bytes, base: int) -> list[Node] | None:
    """尝试把字节完整解析为一个构造型 TLV（用于启发式识别封装的 DER）。"""
    if len(data) < 2:
        return None
    nodes = parse(data, base, eof=False)
    if len(nodes) != 1:
        return None
    n = nodes[0]
    if n.damaged or not n.constructed or n.end - base != len(data):
        return None
    return nodes
