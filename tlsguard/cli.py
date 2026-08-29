"""Command line interface for TLSGuard."""
from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import List

from . import __version__
from .audit import DEFAULT_PORT, audit_host, parse_target
from . import report

_RANK = ["A+", "A", "B", "C", "D", "F", "ERR"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tlsguard",
        description="Audit and harden the TLS posture of your endpoints.",
    )
    parser.add_argument("--version", action="version", version=f"tlsguard {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Audit one or more hosts.")
    scan.add_argument("targets", nargs="*", default=[],
                      help="Hosts to audit, for example example.com or example.com:8443.")
    scan.add_argument("--from-file", metavar="PATH",
                      help="Read targets from a file, one per line.")
    scan.add_argument("--format", choices=["text", "json"], default="text",
                      help="Output format.")
    scan.add_argument("--timeout", type=float, default=8.0,
                      help="Per connection timeout in seconds.")
    scan.add_argument("--min-expiry-days", type=int, default=30,
                      help="Warn when a certificate expires within this many days.")
    scan.add_argument("--concurrency", type=int, default=8,
                      help="How many hosts to audit at once.")
    scan.add_argument("--no-protocols", action="store_true",
                      help="Skip the protocol version probe.")
    scan.add_argument("--no-hsts", action="store_true",
                      help="Skip the HSTS header check.")
    scan.add_argument("--fail-under", metavar="GRADE",
                      help="Exit nonzero if any host grades worse than this, for example B.")
    scan.add_argument("--no-color", action="store_true", help="Disable colored output.")

    sub.add_parser("version", help="Print the version.")
    return parser


def _collect_targets(args) -> List[str]:
    targets = list(args.targets)
    if args.from_file:
        try:
            with open(args.from_file, "r", encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    s = raw.strip()
                    if s and not s.startswith("#"):
                        targets.append(s)
        except OSError as exc:
            print(f"could not read {args.from_file}: {exc}", file=sys.stderr)
    return targets


def _run_scan(args) -> int:
    targets = _collect_targets(args)
    if not targets:
        print("no targets given. pass a host or use --from-file.", file=sys.stderr)
        return 2

    pairs = [parse_target(t, DEFAULT_PORT) for t in targets]

    def run(pair):
        host, port = pair
        return audit_host(
            host, port,
            timeout=args.timeout,
            min_expiry_days=args.min_expiry_days,
            check_protocols=not args.no_protocols,
            check_hsts=not args.no_hsts,
        )

    workers = max(1, min(args.concurrency, len(pairs)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        audits = list(pool.map(run, pairs))

    if args.format == "json":
        print(report.format_json(audits, __version__))
    else:
        use_color = (not args.no_color) and sys.stdout.isatty()
        print(report.format_text(audits, use_color=use_color))

    if args.fail_under:
        threshold = args.fail_under.upper()
        if threshold not in _RANK:
            print(f"unknown grade for --fail-under: {args.fail_under}", file=sys.stderr)
            return 2
        limit = _RANK.index(threshold)
        worst = max((_RANK.index(a.grade) if a.grade in _RANK else len(_RANK) - 1) for a in audits)
        if worst > limit:
            return 1
    return 0


def main(argv: List[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
            return _run_scan(args)
        if args.command == "version":
            print(f"tlsguard {__version__}")
            return 0
        parser.print_help()
        return 0
    except BrokenPipeError:
        import os
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
