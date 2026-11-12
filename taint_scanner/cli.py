"""Command line interface: ``python -m taint_scanner scan <dir> ...``"""

from __future__ import annotations

import argparse
import sys

from .report import write_report
from .scanner import Scanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="taint_scanner",
        description="Offline cross-module Python injection scanner (ast + sqlite only).",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a source directory")
    scan.add_argument("path", help="project root directory to scan")
    scan.add_argument("-o", "--output", help="write JSON report to this file")
    scan.add_argument("--cache-dir", help="directory holding scan_cache.sqlite3")
    scan.add_argument("--no-cache", action="store_true",
                      help="ignore the persistent cache and recompute every summary")
    scan.add_argument("--clear-cache", action="store_true",
                      help="delete the cache before scanning")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "scan":
        return 2
    scanner = Scanner(args.path, cache_dir=args.cache_dir)
    try:
        if args.clear_cache:
            scanner.cache.clear()
        result = scanner.scan(use_cache=not args.no_cache)
        if args.output:
            write_report(result, scanner.root, args.output)
        else:
            from .report import render_json
            sys.stdout.write(render_json(result, scanner.root))
            sys.stdout.write("\n")
    finally:
        scanner.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
