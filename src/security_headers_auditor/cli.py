"""Command-line interface for Security Headers Auditor."""

from __future__ import annotations

import argparse
from pathlib import Path

from .auditor import audit_headers
from .report import render_html, render_json, render_markdown


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
        choices=("markdown", "json", "html"),
        default="markdown",
        help="Report output format.",
    )
    parser.add_argument(
        "--profile",
        choices=("auto", "app", "api", "brochure"),
        default="auto",
        help=(
            "Endpoint profile. Auto uses conservative response evidence; select a "
            "profile explicitly when the endpoint purpose is known."
        ),
    )
    parser.add_argument(
        "--include-query",
        action="store_true",
        help=(
            "Include URL query strings and fragments in reports. They are redacted "
            "by default because they may contain identifiers or secrets."
        ),
    )
    parser.add_argument(
        "--allow-cross-origin-redirects",
        action="store_true",
        help=(
            "Follow redirects that leave the original origin. Same-host HTTP-to-HTTPS "
            "upgrades are allowed by default; use this only for authorized destinations."
        ),
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

    results = [
        audit_headers(
            target,
            timeout=args.timeout,
            profile=args.profile,
            include_query=args.include_query,
            allow_cross_origin_redirects=args.allow_cross_origin_redirects,
        )
        for target in targets
    ]
    renderers = {
        "markdown": render_markdown,
        "json": render_json,
        "html": render_html,
    }
    rendered = renderers[args.format](results)

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
