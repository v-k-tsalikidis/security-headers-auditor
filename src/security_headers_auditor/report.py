"""Report rendering for security header audit results."""

from __future__ import annotations

import json
from dataclasses import asdict

from .auditor import AuditResult, HeaderFinding


def render_markdown(results: list[AuditResult]) -> str:
    lines: list[str] = [
        "# Security Headers Audit Report",
        "",
        "This report is informational and based on read-only HTTP response header checks.",
        "",
        "Scoring focuses on baseline browser security signals. Contextual headers and "
        "information-disclosure observations are reported separately because their value "
        "depends on application type, endpoint sensitivity, and compatibility constraints.",
        "",
    ]

    lines.extend(_render_summary_table(results))
    lines.append("")

    for result in results:
        lines.extend(_render_result_markdown(result))
        lines.append("")

    lines.extend(
        [
            "## Disclaimer",
            "",
            "This tool is an independent educational project. Use it only on systems you own, administer, or are authorized to assess.",
            "",
            "A strong score does not prove that an application is secure. A weak score means that baseline browser-side hardening should be reviewed.",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_json(results: list[AuditResult]) -> str:
    return json.dumps([asdict(result) for result in results], indent=2, sort_keys=True)


def _render_summary_table(results: list[AuditResult]) -> list[str]:
    lines = [
        "## Executive Summary",
        "",
        "| Target | Score | Summary | High | Medium | Low |",
        "| --- | ---: | --- | ---: | ---: | ---: |",
    ]

    for result in results:
        if result.error:
            lines.append(f"| `{_escape_table_cell(result.target)}` | 0 | Error | 0 | 0 | 0 |")
            continue

        severity_counts = _severity_counts(result)
        lines.append(
            "| "
            f"`{_escape_table_cell(result.target)}` | "
            f"{result.score}/100 | "
            f"{result.summary} | "
            f"{severity_counts['high']} | "
            f"{severity_counts['medium']} | "
            f"{severity_counts['low']} |"
        )

    return lines


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
            "### Baseline Findings",
            "",
            "| Header | Status | Severity | Points | Evidence | Recommendation |",
            "| --- | --- | --- | ---: | --- | --- |",
        ]
    )

    for finding in _findings_by_category(result, "baseline"):
        lines.append(_render_finding_row(finding))

    contextual = _findings_by_category(result, "contextual")
    if contextual:
        lines.extend(
            [
                "",
                "### Contextual Checks",
                "",
                "| Header | Status | Evidence / Note | Recommendation |",
                "| --- | --- | --- | --- |",
            ]
        )
        for finding in contextual:
            evidence = finding.value if finding.value else finding.note
            lines.append(
                "| "
                f"`{finding.name}` | "
                f"{finding.status} | "
                f"{_escape_table_cell(evidence)} | "
                f"{_escape_table_cell(finding.recommendation)} |"
            )

    disclosure = _findings_by_category(result, "disclosure")
    if disclosure:
        lines.extend(
            [
                "",
                "### Information-Disclosure Observations",
                "",
                "| Header | Value | Note |",
                "| --- | --- | --- |",
            ]
        )
        for finding in disclosure:
            lines.append(
                "| "
                f"`{finding.name}` | "
                f"{_escape_table_cell(finding.value or '')} | "
                f"{_escape_table_cell(finding.note)} |"
            )

    return lines


def _render_finding_row(finding: HeaderFinding) -> str:
    evidence = finding.value if finding.value else finding.note
    points = f"{finding.points:g}/{finding.max_points}"
    return (
        "| "
        f"`{finding.name}` | "
        f"{finding.status} | "
        f"{finding.severity} | "
        f"{points} | "
        f"{_escape_table_cell(evidence)} | "
        f"{_escape_table_cell(finding.recommendation)} |"
    )


def _findings_by_category(result: AuditResult, category: str) -> list[HeaderFinding]:
    return [finding for finding in result.findings if finding.category == category]


def _severity_counts(result: AuditResult) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in result.findings:
        if finding.status == "pass" or finding.severity == "info":
            continue
        if finding.severity in counts:
            counts[finding.severity] += 1
    return counts


def _escape_table_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
