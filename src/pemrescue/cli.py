"""命令行入口。"""

from __future__ import annotations

import argparse
import sys

from rich.console import Console

from . import __version__
from .analyze import TYPES, analyze_bytes
from .render import Options, render_all


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pemrescue",
        description="从可能被截断的 PEM / DER 文件中尽可能提取证书与密钥信息，以带语义的 ASN.1 树显示。",
        epilog="退出码：0 = 全部完整；1 = 发现截断或损坏；2 = 无法读取输入。",
    )
    p.add_argument("files", nargs="+", metavar="FILE", help="要分析的文件，'-' 表示标准输入")
    p.add_argument("-t", "--type", choices=sorted(TYPES), help="强制按指定结构解析（默认自动识别）")
    p.add_argument("--generic", action="store_true", help="不做语义解析，只显示通用 ASN.1 树")
    p.add_argument("--max-hex", type=int, default=96, metavar="N",
                   help="树中超过 N 字节的值折叠显示（默认 96）；关键字段的完整 hex 见末尾列表")
    p.add_argument("--no-hex", action="store_true", help="不显示十六进制内容")
    p.add_argument("--no-summary", action="store_true", help="不在末尾列出字段的 hex 值")
    p.add_argument("--no-color", action="store_true", help="禁用颜色（输出被重定向时自动禁用）")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console(no_color=args.no_color, highlight=False, soft_wrap=False)
    opts = Options(max_hex=max(16, args.max_hex), show_hex=not args.no_hex,
                   summary=not args.no_summary)
    rc = 0
    for path in args.files:
        try:
            raw = sys.stdin.buffer.read() if path == "-" else open(path, "rb").read()
        except OSError as e:
            console.print(f"[bold red]无法读取 {path}：{e.strerror}[/]")
            rc = 2
            continue
        items = analyze_bytes(raw, force_type=args.type, semantic=not args.generic)
        render_all(console, items, opts, "<stdin>" if path == "-" else path)
        if not items or any(it.damaged for it in items):
            rc = max(rc, 1)
    return rc


if __name__ == "__main__":
    sys.exit(main())
