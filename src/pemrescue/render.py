"""用 rich 把分析结果渲染为终端里的 ASN.1 树。"""

from __future__ import annotations

from dataclasses import dataclass, field

from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree

from . import values as V
from .analyze import Item
from .der import Node, Status

STATUS_TEXT = {
    Status.TRUNCATED: ("截断", "bold red"),
    Status.HEADER_TRUNCATED: ("头部截断", "bold red"),
    Status.OVERFLOW: ("长度越界", "bold red"),
    Status.MALFORMED: ("无法解析", "bold red"),
    Status.MISSING: ("缺失", "red"),
}


@dataclass
class Options:
    max_hex: int = 96  # 超过该字节数时在树中折叠
    show_hex: bool = True
    summary: bool = True  # 末尾输出字段 hex 列表
    width: int = 120
    listed: set[int] = field(default_factory=set)  # 末尾列出的节点 id


def hex_lines(data: bytes, offset: int, opts: Options, truncated: bool, missing: int, depth: int = 0,
              listed: bool = False) -> Text:
    t = Text()
    if len(data) <= opts.max_hex:
        segs: list[tuple[int, int] | None] = [(0, len(data))]
        omitted = 0
    else:
        head = (opts.max_hex * 2 // 3) // 16 * 16 or 16
        tail = 16
        segs = [(0, head), None, (len(data) - tail, len(data))]
        omitted = len(data) - head - tail
    # 根据树的缩进和终端宽度决定每行字节数，避免换行
    per = max(4, min(16, (opts.width - depth * 4 - 9) // 3))
    if per >= 8:
        per -= per % 4
    for seg in segs:
        if seg is None:
            t.append(f"\n      … 省略 {omitted} 字节 …", style="dim italic")
            continue
        a, b = seg
        for i in range(a, b, per):
            chunk = data[i : min(i + per, b)]
            t.append(f"\n{offset + i:6d}: ", style="dim")
            t.append(" ".join(f"{c:02x}" for c in chunk), style="bright_black")
    if truncated:
        t.append(f"\n      ▲ 缺 {missing} 字节" if missing else "\n      ▲ 截断", style="bold red")
    return t


def node_label(n: Node, opts: Options, depth: int = 0) -> Text:
    t = Text()
    if n.status is Status.MISSING:
        t.append("     ✗ ", style="red")
        if n.optional_missing:
            t.append(f"{n.name}  可选，未知", style="red dim")
        else:
            t.append(f"{n.name}  缺失", style="bold red")
        return t

    off = f"{n.offset:6d}" if n.offset >= 0 else "     ?"
    t.append(off + " ", style="dim")
    t.append(V.tag_name(n), style="yellow")
    if n.name:
        t.append(" " + n.name, style="bold cyan")
        if n.guessed:
            t.append("（推测）", style="cyan dim")

    meta = f"  hl={n.header_len}"
    if n.indefinite:
        meta += " l=不定长"
    elif n.length is not None:
        meta += f" l={n.length}"
    t.append(meta, style="dim")

    if n.status in STATUS_TEXT:
        word, style = STATUS_TEXT[n.status]
        detail = ""
        if n.status is Status.TRUNCATED and n.length is not None:
            detail = f" {len(n.content)}/{n.length}"
        t.append(f"  ⚠ {word}{detail}", style=style)

    summary = getattr(n.spec, "summary", None) if n.spec else None
    val = None
    if n.display is not None:
        val = n.display(n)
    elif summary is not None:
        val = summary(n)
    if val is None:
        val = V.describe(n)
    if val:
        t.append("  = ", style="dim")
        t.append(val, style="green" if n.status is Status.COMPLETE else "red")

    for note in n.notes:
        t.append(f"  [{note}]", style="magenta")

    if opts.show_hex and _wants_hex(n) and not (val and n.status is Status.COMPLETE and V.printable(n.content)):
        t.append_text(hex_lines(n.content, n.content_offset, opts,
                                n.status is not Status.COMPLETE, n.missing_bytes, depth,
                                id(n) in opts.listed))
    return t


def _spec_type(spec) -> str | None:
    if spec is None or spec.tags is None:
        return None
    names = sorted({V.UNIVERSAL_NAMES.get(t, f"[{t}]") if c == 0 else f"[{t}]" for c, t in spec.tags})
    return " | ".join(names)


def _wants_hex(n: Node) -> bool:
    if n.constructed or n.encapsulated:
        return n.status is Status.MALFORMED
    if n.status is Status.MALFORMED:
        return True
    if not n.content:
        return False
    if n.cls == 0 and n.tag in {1, 5, 6, 23, 24} | V.STRING_TAGS:
        return False
    if n.cls == 0 and n.tag == 2 and len(n.content) <= 8 and n.status is Status.COMPLETE:
        return False
    return True


def build_tree(n: Node, opts: Options, tree: Tree | None = None, depth: int = 0) -> Tree:
    label = node_label(n, opts, depth)
    branch = Tree(label) if tree is None else tree.add(label)
    for c in n.children:
        build_tree(c, opts, branch, depth + 1)
    if n.encapsulated:
        enc = branch.add(Text("  ↳ 封装内容", style="dim italic"))
        for c in n.encapsulated:
            build_tree(c, opts, enc, depth + 2)
    return branch


def report_nodes(item: Item) -> list[Node]:
    """末尾要列出的字段：标记为 report 的字段，跳过其封装内容已单独列出的外层字段。"""
    out = []
    for top in item.nodes[:1]:
        for n in top.iter_all():
            if n.spec is None or not getattr(n.spec, "report", False) or not n.name:
                continue
            if n.encapsulated and any(
                getattr(c.spec, "report", False) for e in n.encapsulated for c in e.iter_all()
            ):
                continue
            out.append(n)
    return out


def _parents(item: Item) -> dict[int, Node]:
    par: dict[int, Node] = {}

    def walk(n: Node, p: Node | None):
        if p is not None:
            par[id(n)] = p
        for c in n.children:
            walk(c, n)
        for c in n.encapsulated or ():
            walk(c, p if p is not None and n.name is None else n)

    for top in item.nodes:
        walk(top, None)
    return par


def field_value(item: Item, n: Node) -> tuple[bytes, str]:
    """返回 (要输出的字节, 说明)。原始类型输出值本身，构造类型输出完整 DER 编码。"""
    if n.constructed or n.cls is None and n.spec is None:
        return item.tlv_bytes(n), "DER"
    b = n.content
    if n.is_universal(2) and len(b) > 1 and b[0] == 0 and b[1] & 0x80:
        return b[1:], ""
    if n.is_universal(3):
        return b[1:], ""
    return b, ""


def value_dump(console: Console, item: Item, nodes: list[Node]) -> None:
    present = [n for n in nodes if n.status is not Status.MISSING]
    missing = [n for n in nodes if n.status is Status.MISSING and not n.optional_missing]
    if not present and not missing:
        return
    par = _parents(item)

    def base_name(n: Node) -> str:
        return n.alias if n.name == "parameters" and n.alias else n.name

    def owner(n: Node) -> Node | None:
        p = par.get(id(n))
        while p is not None and (p.name == "parameters" or not p.name):
            p = par.get(id(p))
        return p

    names = [base_name(n) for n in present]
    console.print(Text("字段值", style="bold underline"))
    for n in present:
        label = base_name(n)
        p = owner(n)
        if p is not None and (names.count(label) > 1 or n.name == "parameters" or label in ("salt", "nonce")):
            label = f"{p.name}.{label}"
        data, what = field_value(item, n)
        head = Text("\n")
        head.append(label, style="bold cyan")
        if n.damaged:
            want = len(data) + n.missing_bytes if n.length is not None else "?"
            head.append(f"  ⚠ {len(data)}/{want} 字节", style="bold red")
        else:
            head.append(f"  {len(data)} 字节", style="green")
        if what:
            head.append(f"  {what}", style="dim")
        console.print(head)
        console.print(data.hex() if data else "(无数据)", soft_wrap=True, highlight=False, markup=False)
    if missing:
        t = Text("\n缺失：", style="bold red")
        t.append(", ".join(n.name for n in missing), style="red")
        console.print(t)


def render_item(console: Console, idx: int, item: Item, opts: Options, filename: str) -> None:
    b = item.block
    head = Text()
    head.append("名称：", style="dim")
    head.append(f"{filename}\n", style="bold")
    head.append("类型：", style="dim")
    head.append(f"{item.type_name}\n", style="bold cyan")
    have, total = item.completeness()
    head.append("数据：", style="dim")
    if total:
        pct = have / total * 100
        style = "green" if have >= total and not item.damaged else "bold red"
        head.append(f"{have} / {total} 字节（{pct:.1f}%）", style=style)
    else:
        head.append(f"{have} 字节", style="green")
    st = item.stats
    if not b.encrypted_legacy:
        head.append(
            f"\n字段：{st.complete_leaves} 完整，{st.truncated} 截断，{st.missing} 缺失"
            + (f"，{st.missing_optional} 可选未知" if st.missing_optional else ""),
            style="dim",
        )
    if b.headers:
        head.append("\n头部：", style="dim")
        head.append("; ".join(f"{k}: {v}" for k, v in b.headers.items()))
    for note in b.notes:
        head.append(f"\n⚠ {note}", style="bold yellow")
    border = "red" if item.damaged else "green"
    console.print(Panel(head, border_style=border, expand=False))

    if not item.nodes:
        console.print(Text("  无数据", style="red"))
        return
    listed = report_nodes(item) if opts.summary else []
    opts.listed = {id(n) for n in listed}
    for n in item.nodes:
        console.print(build_tree(n, opts))
    if listed:
        console.print()
        value_dump(console, item, listed)
    console.print()


def render_all(console: Console, items: list[Item], opts: Options, filename: str) -> None:
    opts.width = console.width
    if not items:
        console.print(Text(f"{filename}: 没有找到 PEM 块或 DER 数据", style="bold red"))
        return
    for i, it in enumerate(items, 1):
        render_item(console, i, it, opts, filename)


__all__ = ["Options", "render_all", "Group"]
