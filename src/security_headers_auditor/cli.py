"""Command-line interface for Security Headers Auditor."""

from __future__ import annotations

import argparse
from pathlib import Path

from .auditor import audit_headers
from .report import render_json, render_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only HTTP security headers auditor for user-provided targets."
    )
    parser.add_argument("targets", nargs="*", help="Target URLs or hostnames to audit.")
    parser.add_argument(
        "--input-file",
        type=Path,
        help="Plain text file containing one target per line.",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Report output format.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write report to this path instead of stdout.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="HTTP timeout in seconds.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    targets = list(args.targets)
    if args.input_file:
        targets.extend(_read_targets(args.input_file))

    targets = [target for target in (item.strip() for item in targets) if target]
    if not targets:
        parser.error("Provide at least one target or --input-file.")

    results = [audit_headers(target, timeout=args.timeout) for target in targets]
    rendered = render_json(results) if args.format == "json" else render_markdown(results)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered)

    return 0


def _read_targets(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [
        line.strip()
        for line in lines
        if line.strip() and not line.strip().startswith("#")
    ]


if __name__ == "__main__":
    raise SystemExit(main())

