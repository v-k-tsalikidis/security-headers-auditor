"""Report rendering for security header audit results."""

from __future__ import annotations

import json
from dataclasses import asdict

from .auditor import AuditResult


def render_markdown(results: list[AuditResult]) -> str:
    lines: list[str] = [
        "# Security Headers Audit Report",
        "",
        "This report is informational and based on simple HTTP response header checks.",
        "",
    ]

    for result in results:
        lines.extend(_render_result_markdown(result))
        lines.append("")

    lines.extend(
        [
            "## Disclaimer",
            "",
            "This tool is an independent educational project. Use it only on systems you own, administer, or are authorized to assess.",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_json(results: list[AuditResult]) -> str:
    return json.dumps([asdict(result) for result in results], indent=2, sort_keys=True)


def _render_result_markdown(result: AuditResult) -> list[str]:
    lines = [
        f"## {result.target}",
        "",
    ]

    if result.error:
        lines.extend(
            [
                f"- Status: `{result.summary}`",
                f"- Error: `{result.error}`",
            ]
        )
        return lines

    lines.extend(
        [
            f"- Final URL: `{result.final_url}`",
            f"- HTTP status: `{result.status_code}`",
            f"- Score: `{result.score}/100`",
            f"- Summary: `{result.summary}`",
            "",
            "| Header | Status | Value / Note |",
            "| --- | --- | --- |",
        ]
    )

    for finding in result.findings:
        value = finding.value if finding.value else finding.note
        lines.append(f"| `{finding.name}` | {finding.status} | {value} |")

    return lines

