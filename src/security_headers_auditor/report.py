"""Markdown, JSON, and self-contained HTML report rendering."""

from __future__ import annotations

import json
from dataclasses import asdict
from html import escape
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from . import METHODOLOGY_VERSION
from .auditor import AuditResult, HeaderFinding
from .catalog import CITATIONS, Citation
from .compliance import MAPPING_SET_VERSION

if TYPE_CHECKING:
    from .assurance import AssuranceRun


def render_markdown(
    results: list[AuditResult],
    assurance_run: AssuranceRun | None = None,
) -> str:
    lines: list[str] = [
        "# Security Headers Audit Report",
        "",
        f"Methodology version: `{METHODOLOGY_VERSION}`",
        f"Evidence mapping set: `{MAPPING_SET_VERSION}`",
        "",
        "This read-only assessment applies response-profile expectations rather than a flat "
        "header checklist. Auto-detection is evidence-based but must be overridden when the "
        "operator knows the endpoint purpose.",
        "",
    ]
    lines.extend(_render_summary_table(results))
    lines.append("")
    if assurance_run is not None:
        lines.extend(_render_assurance_markdown(assurance_run))
        lines.append("")

    for result in results:
        lines.extend(_render_result_markdown(result))
        lines.append("")

    lines.extend(_render_markdown_references(results))
    lines.extend(
        [
            "",
            "## Interpretation And Authorization",
            "",
            "Use this tool only on systems you own, administer, or are authorized to assess. "
            "A strong score does not prove that an application is secure. Findings are "
            "configuration review signals, not evidence of compromise or regulatory compliance.",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_json(results: list[AuditResult]) -> str:
    return json.dumps(
        {
            "methodology_version": METHODOLOGY_VERSION,
            "mapping_set_version": MAPPING_SET_VERSION,
            "results": [asdict(result) for result in results],
        },
        indent=2,
        sort_keys=True,
    )


def render_html(
    results: list[AuditResult],
    assurance_run: AssuranceRun | None = None,
) -> str:
    """Render an offline, dependency-free, escaped HTML report."""
    body = [
        '<a class="skip-link" href="#main-content">Skip to report content</a>',
        '<header class="report-header">',
        '  <div>',
        '    <p class="document-type">Independent security assessment</p>',
        "    <h1>Security Headers Audit Report</h1>",
        "  </div>",
        '  <dl class="report-meta">',
        "    <div><dt>Methodology</dt><dd>v" + METHODOLOGY_VERSION + "</dd></div>",
        "    <div><dt>Evidence</dt><dd>" + MAPPING_SET_VERSION + "</dd></div>",
        "    <div><dt>Targets</dt><dd>" + str(len(results)) + "</dd></div>",
        "    <div><dt>Processing</dt><dd>Local report</dd></div>",
        "  </dl>",
        "</header>",
        '<main id="main-content">',
        _render_html_executive_summary(results),
        _render_html_target_summary(results),
    ]
    if assurance_run is not None:
        body.append(_render_html_assurance_summary(assurance_run))
    for index, result in enumerate(results):
        body.append(_render_html_result(result, index))
    body.extend(
        [
            _render_html_references(results),
            _render_html_guardrails(),
            "</main>",
            '<footer class="report-footer">',
            "  <p>Security Headers Auditor v"
            + METHODOLOGY_VERSION
            + " &middot; Independent, read-only, public-safe assessment.</p>",
            "</footer>",
        ]
    )

    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '  <meta charset="utf-8">',
            '  <meta name="viewport" content="width=device-width, initial-scale=1">',
            '  <meta name="color-scheme" content="light">',
            (
                '  <meta http-equiv="Content-Security-Policy" '
                'content="default-src \'none\'; style-src \'unsafe-inline\'; '
                "img-src data:; font-src 'none'; script-src 'none'; connect-src 'none'; "
                "object-src 'none'; base-uri 'none'; form-action 'none'\">"
            ),
            "  <title>Security Headers Audit Report</title>",
            "  <style>",
            _HTML_CSS,
            "  </style>",
            "</head>",
            "<body>",
            *body,
            "</body>",
            "</html>",
            "",
        ]
    )


def _render_summary_table(results: list[AuditResult]) -> list[str]:
    lines = [
        "## Executive Summary",
        "",
        "| Target | Profile | Confidence | Score | Summary | High | Medium | Low |",
        "| --- | --- | --- | ---: | --- | ---: | ---: | ---: |",
    ]
    for result in results:
        if result.error:
            lines.append(
                f"| `{_escape_markdown_cell(result.target)}` | Error | - | 0 | Error | 0 | 0 | 0 |"
            )
            continue
        counts = _severity_counts(result)
        lines.append(
            "| "
            f"`{_escape_markdown_cell(result.target)}` | "
            f"{_escape_markdown_cell(result.profile_label or '')} | "
            f"{_escape_markdown_cell(result.profile_confidence or '')} | "
            f"{result.score}/100 | "
            f"{result.summary} | "
            f"{counts['high']} | {counts['medium']} | {counts['low']} |"
        )
    return lines


def _render_result_markdown(result: AuditResult) -> list[str]:
    lines = [f"## {_escape_markdown_text(result.target)}", ""]
    if result.error:
        lines.extend(
            [
                f"- Status: `{_escape_markdown_inline_code(result.summary)}`",
                f"- Error: `{_escape_markdown_inline_code(result.error)}`",
            ]
        )
        return lines

    lines.extend(
        [
            f"- Final URL: `{_escape_markdown_inline_code(result.final_url or '')}`",
            f"- HTTP status: `{result.status_code}`",
            f"- Profile: `{_escape_markdown_inline_code(result.profile_label or '')}` "
            f"(`{_escape_markdown_inline_code(result.selected_profile or '')}`)",
            "- Detection confidence: "
            f"`{_escape_markdown_inline_code(result.profile_confidence or '')}`",
            f"- Score: `{result.score}/100`",
            f"- Summary: `{_escape_markdown_inline_code(result.summary)}`",
            "",
            "### Profile Decision",
            "",
        ]
    )
    lines.extend(
        f"- {_escape_markdown_text(evidence)}"
        for evidence in result.profile_evidence
    )
    lines.extend(
        [
            "",
            "### Profile-Scored Findings",
            "",
            "| Header | Applicability | Status | Severity | Points | Evidence | References |",
            "| --- | --- | --- | --- | ---: | --- | --- |",
        ]
    )
    for finding in _findings_by_category(result, "scored"):
        lines.append(_render_finding_row(finding))

    contextual = _findings_by_category(result, "contextual")
    assurance = _findings_by_category(result, "assurance")
    if assurance:
        lines.extend(
            [
                "",
                "### Assurance Controls",
                "",
                "| Control | Expectation | Status | Severity | Evidence / Note | Mappings |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for finding in assurance:
            evidence = finding.value if finding.value else finding.note
            lines.append(
                "| "
                f"`{finding.name}` | {finding.applicability} | {finding.status} | "
                f"{finding.severity} | {_escape_markdown_cell(evidence)} | "
                f"{_escape_markdown_cell(', '.join(mapping.label for mapping in finding.evidence_mappings))} |"
            )

    if contextual:
        lines.extend(
            [
                "",
                "### Contextual Findings",
                "",
                "| Header | Applicability | Status | Evidence / Note | References |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for finding in contextual:
            evidence = finding.value if finding.value else finding.note
            lines.append(
                "| "
                f"`{finding.name}` | {finding.applicability} | {finding.status} | "
                f"{_escape_markdown_cell(evidence)} | "
                f"{_escape_markdown_cell(', '.join(finding.citation_keys))} |"
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
                f"{_escape_markdown_cell(finding.value or '')} | "
                f"{_escape_markdown_cell(finding.note)} |"
            )
    return lines


def _render_finding_row(finding: HeaderFinding) -> str:
    evidence = finding.value if finding.value else finding.note
    points = f"{finding.points:g}/{finding.max_points}"
    return (
        "| "
        f"`{finding.name}` | {finding.applicability} | {finding.status} | "
        f"{finding.severity} | {points} | {_escape_markdown_cell(evidence)} | "
        f"{_escape_markdown_cell(', '.join(finding.citation_keys))} |"
    )


def _render_markdown_references(results: list[AuditResult]) -> list[str]:
    citations = _citations_for_results(results)
    lines = ["## Standards And Research", ""]
    for citation in citations:
        lines.append(
            f"- **{citation.key}**: [{citation.title}]({citation.url}) - "
            f"{citation.publisher}, {citation.source_type}; accessed {citation.accessed}."
        )
    return lines


def _render_html_executive_summary(results: list[AuditResult]) -> str:
    successful = [result for result in results if not result.error]
    aggregate_score = round(
        sum(result.score for result in successful) / len(successful)
    ) if successful else 0
    counts = _aggregate_status_counts(successful)
    summary = _score_label(aggregate_score) if successful else "No successful assessments"
    return f"""
<section class="executive-summary" aria-labelledby="executive-heading">
  <div class="section-heading">
    <h2 id="executive-heading">Executive Summary</h2>
    <p>Profile-aware assessment of the supplied HTTP responses.</p>
  </div>
  <div class="summary-rail">
    <div class="score-block">
      <span class="metric-label">Aggregate score</span>
      <strong>{aggregate_score}<span> / 100</span></strong>
      <progress value="{aggregate_score}" max="100" aria-label="Aggregate score {aggregate_score} out of 100">{aggregate_score}</progress>
      <span class="metric-note">{escape(summary)}</span>
    </div>
    {_metric("Passed", counts["pass"])}
    {_metric("Warnings", counts["warning"] + counts["review"])}
    {_metric("Missing", counts["missing"])}
    {_metric("Not applicable", counts["not_applicable"])}
    {_metric("Errors", len(results) - len(successful))}
  </div>
</section>""".strip()


def _render_html_target_summary(results: list[AuditResult]) -> str:
    rows: list[str] = []
    for result in results:
        if result.error:
            rows.append(
                "<tr>"
                f"<td>{_code(result.target)}</td><td>Error</td><td>-</td>"
                f"<td>0 / 100</td><td>{escape(result.error)}</td>"
                "</tr>"
            )
            continue
        rows.append(
            "<tr>"
            f"<td>{_code(result.target)}</td>"
            f"<td>{escape(result.profile_label or '')}</td>"
            f"<td>{escape((result.profile_confidence or '').title())}</td>"
            f"<td>{result.score} / 100</td>"
            f"<td>{escape(result.summary)}</td>"
            "</tr>"
        )
    return f"""
<section class="target-summary" aria-labelledby="targets-heading">
  <div class="section-heading">
    <h2 id="targets-heading">Target Summary</h2>
    <p>Queries and fragments are redacted unless explicitly retained by the operator.</p>
  </div>
  <div class="table-scroll" tabindex="0" aria-label="Scrollable target summary">
    <table>
      <thead><tr><th scope="col">Target</th><th scope="col">Profile</th><th scope="col">Confidence</th><th scope="col">Score</th><th scope="col">Assessment</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </div>
</section>""".strip()


def _render_html_result(result: AuditResult, index: int) -> str:
    heading_id = f"target-{index + 1}"
    if result.error:
        return f"""
<section id="{heading_id}-result" class="target-result error-result" aria-labelledby="{heading_id}">
  <div class="target-heading">
    <div><p class="target-index">Target {index + 1}</p><h2 id="{heading_id}">{escape(result.target)}</h2></div>
    {_status_badge("error")}
  </div>
  <p>{escape(result.error)}</p>
</section>""".strip()

    profile_evidence = "".join(f"<li>{escape(item)}</li>" for item in result.profile_evidence)
    scored = _findings_by_category(result, "scored")
    contextual = _findings_by_category(result, "contextual")
    assurance = _findings_by_category(result, "assurance")
    disclosure = _findings_by_category(result, "disclosure")
    first_actionable = next(
        (finding.key for finding in scored if finding.status in {"missing", "warning"}),
        None,
    )
    return f"""
<section id="{heading_id}-result" class="target-result" aria-labelledby="{heading_id}">
  <div class="target-heading">
    <div>
      <p class="target-index">Target {index + 1}</p>
      <h2 id="{heading_id}">{escape(result.target)}</h2>
      <p class="target-url">Final response: {_code(result.final_url or '')} &middot; HTTP {result.status_code}</p>
    </div>
    <div class="target-score"><span>Score</span><strong>{result.score}<small> / 100</small></strong><em>{escape(result.summary)}</em></div>
  </div>
  <div class="profile-band">
    <div><span>Response profile</span><strong>{escape(result.profile_label or '')}</strong></div>
    <div><span>Detection confidence</span><strong>{escape((result.profile_confidence or '').title())}</strong></div>
    <div class="profile-evidence"><span>Decision evidence</span><ul>{profile_evidence}</ul></div>
  </div>
  {_render_html_finding_group("Profile-Scored Findings", scored, first_actionable)}
  {_render_html_finding_group("Assurance Controls", assurance, None)}
  {_render_html_finding_group("Contextual Findings", contextual, None)}
  {_render_html_disclosure(disclosure)}
</section>""".strip()


def _render_html_finding_group(
    title: str,
    findings: list[HeaderFinding],
    open_key: str | None,
) -> str:
    if not findings:
        return ""
    rendered = "".join(
        _render_html_finding(finding, open_by_default=finding.key == open_key)
        for finding in findings
    )
    return f"""
<section class="finding-group" aria-label="{escape(title)}">
  <h3>{escape(title)}</h3>
  <div class="finding-list">{rendered}</div>
</section>""".strip()


def _render_html_finding(
    finding: HeaderFinding,
    open_by_default: bool,
) -> str:
    evidence = finding.value if finding.value is not None else "Header not observed."
    mappings = _render_html_evidence_mappings(finding)
    citation_links = "".join(
        _citation_link(CITATIONS[key])
        for key in finding.citation_keys
        if key in CITATIONS
    )
    points = (
        f"{finding.points:g} / {finding.max_points}"
        if finding.max_points
        else "Not scored"
    )
    open_attribute = " open" if open_by_default else ""
    return f"""
<details class="finding finding-{_status_class(finding.status)}" data-finding-key="{escape(finding.key, quote=True)}"{open_attribute}>
  <summary>
    <span class="disclosure-marker" aria-hidden="true"></span>
    <span class="finding-name">{escape(finding.name)}</span>
    {_status_badge(finding.status)}
    <span class="finding-applicability">{escape(finding.applicability.replace('_', ' ').title())}</span>
    <span class="finding-points">{escape(points)}</span>
  </summary>
  <div class="finding-body">
    <div class="finding-column evidence-column">
      <h4>Evidence</h4>
      <pre><code>{escape(evidence)}</code></pre>
      <dl>
        <div><dt>Severity</dt><dd>{escape(finding.severity.title())}</dd></div>
        <div><dt>Assessment</dt><dd>{escape(finding.note)}</dd></div>
      </dl>
    </div>
    <div class="finding-column">
      <h4>Recommendation</h4>
      <p>{escape(finding.recommendation)}</p>
      <h4>Scoring rationale</h4>
      <p>{escape(finding.scoring_rationale)}</p>
    </div>
    <div class="finding-column research-column">
      <h4>Evidence mappings</h4>
      {mappings}
      <h4>Research and specifications</h4>
      <ul class="citation-list">{citation_links}</ul>
    </div>
  </div>
</details>""".strip()


def _render_html_disclosure(findings: list[HeaderFinding]) -> str:
    if not findings:
        return ""
    rows = "".join(
        "<tr>"
        f"<th scope=\"row\">{escape(finding.name)}</th>"
        f"<td><code>{escape(finding.value or '')}</code></td>"
        f"<td>{escape(finding.note)}</td>"
        "</tr>"
        for finding in findings
    )
    return f"""
<section class="disclosure-section" aria-labelledby="disclosure-heading">
  <h3 id="disclosure-heading">Information-Disclosure Observations</h3>
  <div class="table-scroll" tabindex="0" aria-label="Scrollable disclosure observations">
    <table><thead><tr><th scope="col">Header</th><th scope="col">Observed value</th><th scope="col">Interpretation</th></tr></thead><tbody>{rows}</tbody></table>
  </div>
</section>""".strip()


def _render_html_references(results: list[AuditResult]) -> str:
    items = "".join(_citation_link(citation, include_type=True) for citation in _citations_for_results(results))
    return f"""
<section class="references" aria-labelledby="references-heading">
  <div class="section-heading">
    <h2 id="references-heading">Standards And Research</h2>
    <p>Mappings are evidence links and control-informed relationships, not compliance certification.</p>
  </div>
  <ol>{items}</ol>
</section>""".strip()


def _render_html_guardrails() -> str:
    return """
<section class="guardrails" aria-labelledby="guardrails-heading">
  <div class="section-heading">
    <h2 id="guardrails-heading">Interpretation And Authorization</h2>
  </div>
  <div class="guardrail-columns">
    <div><h3>Authorization</h3><p>Assess only systems you own, administer, or have explicit authorization to test.</p></div>
    <div><h3>Interpretation</h3><p>A strong score does not prove security. A weak score identifies configuration review work, not active compromise.</p></div>
    <div><h3>Data handling</h3><p>The report is generated locally. Target query strings and fragments are redacted by default.</p></div>
  </div>
</section>""".strip()


def _citation_link(citation: Citation, include_type: bool = False) -> str:
    href = _safe_href(citation.url)
    suffix = (
        f" <span>{escape(citation.publisher)} &middot; "
        f"{escape(citation.source_type)} &middot; accessed {escape(citation.accessed)}</span>"
        if include_type
        else f" <span>{escape(citation.publisher)}</span>"
    )
    return (
        f'<li><a href="{escape(href, quote=True)}" target="_blank" '
        f'rel="noopener noreferrer">{escape(citation.title)}</a>{suffix}</li>'
    )


def _citations_for_results(results: list[AuditResult]) -> list[Citation]:
    keys = {
        key
        for result in results
        for finding in result.findings
        for key in finding.citation_keys
    }
    return [CITATIONS[key] for key in sorted(keys) if key in CITATIONS]


def _aggregate_status_counts(results: list[AuditResult]) -> dict[str, int]:
    counts = {
        "pass": 0,
        "warning": 0,
        "review": 0,
        "missing": 0,
        "not_applicable": 0,
    }
    for result in results:
        for finding in result.findings:
            if finding.status in counts:
                counts[finding.status] += 1
    return counts


def _severity_counts(result: AuditResult) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in result.findings:
        if finding.status in {"pass", "info", "not_applicable"}:
            continue
        if finding.severity in counts:
            counts[finding.severity] += 1
    return counts


def _findings_by_category(result: AuditResult, category: str) -> list[HeaderFinding]:
    return [finding for finding in result.findings if finding.category == category]


def _metric(label: str, value: int) -> str:
    return (
        '<div class="summary-metric">'
        f'<span class="metric-label">{escape(label)}</span>'
        f"<strong>{value}</strong>"
        "</div>"
    )


def _status_badge(status: str) -> str:
    label = status.replace("_", " ").title()
    return f'<span class="status status-{_status_class(status)}">{escape(label)}</span>'


def _status_class(status: str) -> str:
    allowed = {
        "pass",
        "warning",
        "review",
        "missing",
        "info",
        "not_applicable",
        "observed",
        "error",
    }
    return status if status in allowed else "info"


def _score_label(score: int) -> str:
    if score >= 85:
        return "Strong profile alignment"
    if score >= 60:
        return "Moderate profile alignment"
    if score >= 35:
        return "Configuration review required"
    return "Material baseline gaps"


def _safe_href(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        return "#"
    return url


def _code(value: str) -> str:
    return f"<code>{escape(value)}</code>"


def _escape_markdown_cell(value: str) -> str:
    return _escape_markdown_text(value).replace("|", "\\|").replace("`", "&#96;")


def _escape_markdown_inline_code(value: str) -> str:
    return _escape_markdown_text(value).replace("`", "&#96;")


def _escape_markdown_text(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\r", " ")
        .replace("\n", " ")
    )


_HTML_CSS = """
:root {
  color-scheme: light;
  --canvas: #faf9f6;
  --surface: #ffffff;
  --surface-muted: #f4f3ef;
  --text: #1c1d1f;
  --muted: #62656a;
  --border: #d9d9d3;
  --border-soft: #e8e7e2;
  --link: #24558a;
  --pass: #2f6b4f;
  --pass-bg: #eaf3ed;
  --warning: #875d08;
  --warning-bg: #fbf1d7;
  --missing: #9a403d;
  --missing-bg: #f8e9e7;
  --info: #4f5d67;
  --info-bg: #edf0f1;
  --focus: #24558a;
  --radius: 6px;
}

* { box-sizing: border-box; }

html { background: var(--canvas); }

body {
  margin: 0;
  color: var(--text);
  background: var(--canvas);
  font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 15px;
  line-height: 1.55;
  letter-spacing: 0;
}

a { color: var(--link); text-underline-offset: 0.15em; }
a:hover { text-decoration-thickness: 2px; }
a:focus-visible, summary:focus-visible, [tabindex="0"]:focus-visible {
  outline: 3px solid var(--focus);
  outline-offset: 3px;
}

.skip-link {
  position: fixed;
  top: 12px;
  left: 12px;
  z-index: 10;
  padding: 9px 12px;
  color: #fff;
  background: var(--text);
  transform: translateY(-160%);
}
.skip-link:focus { transform: translateY(0); }

.report-header, main, .report-footer {
  width: min(1420px, calc(100% - 48px));
  margin-inline: auto;
}

.report-header {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 32px;
  padding: 34px 4px 20px;
  border-bottom: 1px solid var(--text);
}

.document-type, .target-index {
  margin: 0 0 4px;
  color: var(--muted);
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
}

h1, h2, h3, h4, p { letter-spacing: 0; }
h1 { margin: 0; font-size: 30px; line-height: 1.15; }
h2 { margin: 0; font-size: 19px; line-height: 1.25; }
h3 { margin: 0; font-size: 15px; line-height: 1.35; }
h4 { margin: 0 0 8px; font-size: 13px; }

.report-meta {
  display: flex;
  gap: 26px;
  margin: 0;
}
.report-meta div { padding-left: 18px; border-left: 1px solid var(--border); }
.report-meta dt, .metric-label, .profile-band span, .target-score span {
  color: var(--muted);
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
}
.report-meta dd { margin: 2px 0 0; font-weight: 650; }

main > section { padding: 24px 4px; border-bottom: 1px solid var(--border); }
.section-heading {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 24px;
  margin-bottom: 14px;
}
.section-heading p { margin: 0; color: var(--muted); font-size: 13px; }

.summary-rail {
  display: grid;
  grid-template-columns: minmax(260px, 1.55fr) repeat(5, minmax(100px, 0.75fr));
  border-top: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
}
.summary-rail > div { min-width: 0; padding: 17px 20px; border-left: 1px solid var(--border); }
.summary-rail > div:first-child { border-left: 0; padding-left: 0; }
.assurance-summary .summary-rail {
  grid-template-columns: repeat(3, minmax(140px, 1fr));
  margin-bottom: 16px;
}
.assurance-summary .summary-rail > div:first-child { padding-left: 20px; }
.score-block strong { display: block; margin-top: 4px; font-size: 38px; line-height: 1; }
.score-block strong span { color: var(--muted); font-size: 17px; font-weight: 600; }
.score-block progress {
  display: block;
  width: 100%;
  height: 5px;
  margin: 13px 0 7px;
  border: 0;
  background: var(--border-soft);
}
.score-block progress::-webkit-progress-bar { background: var(--border-soft); }
.score-block progress::-webkit-progress-value { background: var(--text); }
.score-block progress::-moz-progress-bar { background: var(--text); }
.metric-note { color: var(--muted); font-size: 12px; }
.summary-metric strong { display: block; margin-top: 8px; font-size: 24px; line-height: 1; }

.table-scroll { overflow-x: auto; border: 1px solid var(--border); background: var(--surface); }
table { width: 100%; border-collapse: collapse; }
.target-summary table { min-width: 760px; }
.target-summary code { white-space: nowrap; }
.disclosure-section table { min-width: 640px; }
th, td { padding: 10px 13px; border-bottom: 1px solid var(--border-soft); text-align: left; vertical-align: top; }
thead th { color: var(--muted); background: var(--surface-muted); font-size: 11px; text-transform: uppercase; }
tbody tr:last-child th, tbody tr:last-child td { border-bottom: 0; }
code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.9em;
  overflow-wrap: anywhere;
}

.target-result { padding-top: 32px; }
.target-heading {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 32px;
}
.target-heading h2 { overflow-wrap: anywhere; font-size: 22px; }
.target-url { margin: 7px 0 0; color: var(--muted); font-size: 13px; }
.target-score { flex: 0 0 auto; min-width: 120px; text-align: right; }
.target-score strong { display: block; font-size: 30px; line-height: 1; }
.target-score small { color: var(--muted); font-size: 14px; }
.target-score em { display: block; margin-top: 4px; color: var(--muted); font-size: 12px; font-style: normal; }

.profile-band {
  display: grid;
  grid-template-columns: minmax(210px, 0.7fr) minmax(170px, 0.45fr) minmax(340px, 1.5fr);
  margin: 20px 0 24px;
  background: var(--surface-muted);
  border-block: 1px solid var(--border);
}
.profile-band > div { padding: 14px 18px; border-left: 1px solid var(--border); }
.profile-band > div:first-child { border-left: 0; }
.profile-band strong { display: block; margin-top: 3px; }
.profile-band ul { margin: 4px 0 0; padding-left: 18px; color: var(--muted); font-size: 12px; }

.finding-group { margin-top: 24px; }
.finding-group > h3, .disclosure-section > h3 { margin-bottom: 10px; }
.finding-list { border-top: 1px solid var(--border); }
.finding { background: transparent; border-bottom: 1px solid var(--border); }
.finding summary {
  display: grid;
  grid-template-columns: 18px minmax(240px, 1.5fr) 118px minmax(135px, 0.65fr) 90px;
  align-items: center;
  gap: 14px;
  min-height: 49px;
  padding: 7px 4px;
  cursor: pointer;
  list-style: none;
}
.finding summary::-webkit-details-marker { display: none; }
.disclosure-marker {
  width: 8px;
  height: 8px;
  border-right: 1.5px solid currentColor;
  border-bottom: 1.5px solid currentColor;
  transform: rotate(-45deg);
}
.finding[open] .disclosure-marker { transform: rotate(45deg) translate(-2px, -2px); }
.finding-name { font-weight: 700; overflow-wrap: anywhere; }
.finding-applicability, .finding-points { color: var(--muted); font-size: 12px; }
.finding-points { text-align: right; font-variant-numeric: tabular-nums; }

.status {
  display: inline-flex;
  width: fit-content;
  align-items: center;
  min-height: 22px;
  padding: 2px 7px;
  border: 1px solid currentColor;
  border-radius: 3px;
  font-size: 10px;
  font-weight: 750;
  text-transform: uppercase;
}
.status-pass { color: var(--pass); background: var(--pass-bg); }
.status-warning, .status-review { color: var(--warning); background: var(--warning-bg); }
.status-missing, .status-error { color: var(--missing); background: var(--missing-bg); }
.status-info, .status-not_applicable, .status-observed { color: var(--info); background: var(--info-bg); }

.finding-body {
  display: grid;
  grid-template-columns: minmax(280px, 1.25fr) minmax(240px, 1fr) minmax(280px, 1.1fr);
  background: var(--surface);
  border-top: 1px solid var(--border-soft);
}
.finding-column { min-width: 0; padding: 18px; border-left: 1px solid var(--border-soft); }
.finding-column:first-child { border-left: 0; }
.finding-column p { margin: 0 0 17px; color: #35373a; }
pre {
  max-height: 180px;
  margin: 0 0 14px;
  padding: 11px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
  background: var(--surface-muted);
  border: 1px solid var(--border);
  border-radius: 3px;
}
.finding-column dl { margin: 0; }
.finding-column dl div { margin-top: 9px; }
.finding-column dt { color: var(--muted); font-size: 11px; font-weight: 700; text-transform: uppercase; }
.finding-column dd { margin: 2px 0 0; }
.finding-column ul, .citation-list { margin: 0 0 16px; padding-left: 18px; }
.citation-list li { margin-bottom: 7px; }
.citation-list span, .references li span { display: block; color: var(--muted); font-size: 11px; }
.mapping-list li { margin-bottom: 11px; }
.mapping-list span, .mapping-list small {
  display: block;
  margin-top: 3px;
  color: var(--muted);
  font-size: 11px;
}

.disclosure-section { margin-top: 24px; }
.references ol { columns: 2; column-gap: 46px; margin: 0; padding-left: 22px; }
.references li { break-inside: avoid; margin: 0 0 12px; padding-left: 4px; }

.guardrail-columns { display: grid; grid-template-columns: repeat(3, 1fr); border-block: 1px solid var(--border); }
.guardrail-columns div { padding: 15px 18px; border-left: 1px solid var(--border); }
.guardrail-columns div:first-child { border-left: 0; padding-left: 0; }
.guardrail-columns p { margin: 5px 0 0; color: var(--muted); font-size: 13px; }
.error-result p { color: var(--missing); }

.report-footer { padding: 18px 4px 34px; color: var(--muted); font-size: 12px; }
.report-footer p { margin: 0; }

@media (max-width: 980px) {
  .summary-rail { grid-template-columns: 1.5fr repeat(2, 1fr); }
  .summary-rail > div:nth-child(4) { border-left: 0; }
  .profile-band { grid-template-columns: 1fr 1fr; }
  .profile-evidence { grid-column: 1 / -1; border-top: 1px solid var(--border); border-left: 0 !important; }
  .finding-body { grid-template-columns: 1fr; }
  .finding-column { border-top: 1px solid var(--border-soft); border-left: 0; }
  .finding-column:first-child { border-top: 0; }
  .references ol { columns: 1; }
}

@media (max-width: 680px) {
  .report-header, main, .report-footer { width: min(100% - 28px, 1420px); }
  .report-header, .target-heading, .section-heading { align-items: flex-start; flex-direction: column; }
  .report-meta {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    width: 100%;
    gap: 0;
  }
  .report-meta div {
    min-width: 0;
    padding: 10px 12px;
    border-top: 1px solid var(--border);
  }
  .report-meta div:nth-child(odd) { padding-left: 0; border-left: 0; }
  .report-meta div:nth-child(-n + 2) { border-top: 0; }
  h1 { font-size: 25px; }
  .summary-rail { grid-template-columns: 1fr 1fr; }
  .summary-rail > div { border-top: 1px solid var(--border); }
  .summary-rail > div:nth-child(odd) { border-left: 0; }
  .summary-rail > div:first-child { grid-column: 1 / -1; border-top: 0; }
  .assurance-summary .summary-rail { grid-template-columns: 1fr; }
  .assurance-summary .summary-rail > div { border-left: 0; }
  .target-score { text-align: left; }
  .profile-band { grid-template-columns: 1fr; }
  .profile-band > div { border-top: 1px solid var(--border); border-left: 0; }
  .profile-band > div:first-child { border-top: 0; }
  .profile-evidence { grid-column: auto; }
  .finding summary {
    grid-template-columns: 18px minmax(0, 1fr) auto;
    gap: 9px;
    padding-block: 10px;
  }
  .finding-applicability, .finding-points { grid-column: 2 / -1; text-align: left; }
  .guardrail-columns { grid-template-columns: 1fr; }
  .guardrail-columns div { border-top: 1px solid var(--border); border-left: 0; padding-inline: 0; }
  .guardrail-columns div:first-child { border-top: 0; }
}

@media (prefers-reduced-motion: reduce) {
  * { scroll-behavior: auto !important; }
}

@media print {
  :root { --canvas: #ffffff; --surface-muted: #f4f4f4; }
  body { font-size: 11px; }
  .skip-link { display: none; }
  .report-header, main, .report-footer { width: 100%; }
  .finding { break-inside: avoid; }
  .finding:not([open]) .finding-body { display: none; }
  a { color: inherit; text-decoration: none; }
}
""".strip()


def _render_assurance_markdown(run: AssuranceRun) -> list[str]:
    lines = [
        "## Continuous Assurance",
        "",
        f"- Policy: `{_escape_markdown_inline_code(run.policy_name)}`",
        f"- Outcome: `{run.outcome}`",
        f"- Exit code: `{run.exit_code}`",
        f"- Policy violations: `{len(run.policy_violations)}`",
        f"- Regressions: `{len(run.regressions)}`",
        f"- Operational errors: `{len(run.operational_errors)}`",
    ]
    diagnostics = [
        *(
            (
                violation.target_id,
                violation.code,
                violation.severity,
                violation.control_key or "",
                violation.message,
            )
            for violation in run.policy_violations
        ),
        *(
            (
                regression.target_id,
                regression.code,
                regression.severity,
                regression.control_key or "",
                regression.message,
            )
            for regression in run.regressions
        ),
    ]
    if diagnostics:
        lines.extend(
            [
                "",
                "| Target | Diagnostic | Severity | Control | Detail |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for target, code, severity, control, message in diagnostics:
            lines.append(
                "| "
                f"{_escape_markdown_cell(target)} | "
                f"{_escape_markdown_cell(code)} | "
                f"{_escape_markdown_cell(severity)} | "
                f"{_escape_markdown_cell(control)} | "
                f"{_escape_markdown_cell(message)} |"
            )
    if run.operational_errors:
        lines.extend(["", "### Operational Errors", ""])
        lines.extend(
            f"- {_escape_markdown_text(message)}"
            for message in run.operational_errors
        )
    return lines


def _render_html_assurance_summary(run: AssuranceRun) -> str:
    diagnostics = [
        *(
            (
                violation.target_id,
                violation.code,
                violation.severity,
                violation.control_key or "",
                violation.message,
            )
            for violation in run.policy_violations
        ),
        *(
            (
                regression.target_id,
                regression.code,
                regression.severity,
                regression.control_key or "",
                regression.message,
            )
            for regression in run.regressions
        ),
    ]
    rows = "".join(
        "<tr>"
        f"<td>{escape(target)}</td>"
        f"<td><code>{escape(code)}</code></td>"
        f"<td>{_status_badge('error' if severity == 'high' else 'review')}</td>"
        f"<td>{escape(control)}</td>"
        f"<td>{escape(message)}</td>"
        "</tr>"
        for target, code, severity, control, message in diagnostics
    )
    diagnostic_table = (
        '<div class="table-scroll" tabindex="0" aria-label="Scrollable assurance diagnostics">'
        "<table><thead><tr><th scope=\"col\">Target</th><th scope=\"col\">Diagnostic</th>"
        "<th scope=\"col\">Severity</th><th scope=\"col\">Control</th>"
        f"<th scope=\"col\">Detail</th></tr></thead><tbody>{rows}</tbody></table></div>"
        if rows
        else "<p>No policy violations or regressions were detected.</p>"
    )
    errors = (
        "<ul>"
        + "".join(f"<li>{escape(message)}</li>" for message in run.operational_errors)
        + "</ul>"
        if run.operational_errors
        else ""
    )
    return f"""
<section class="assurance-summary" aria-labelledby="assurance-heading">
  <div class="section-heading">
    <h2 id="assurance-heading">Continuous Assurance</h2>
    <p>Policy <strong>{escape(run.policy_name)}</strong> &middot; outcome <strong>{escape(run.outcome)}</strong> &middot; exit code <strong>{run.exit_code}</strong></p>
  </div>
  <div class="summary-rail">
    {_metric("Policy violations", len(run.policy_violations))}
    {_metric("Regressions", len(run.regressions))}
    {_metric("Operational errors", len(run.operational_errors))}
  </div>
  {diagnostic_table}
  {errors}
</section>""".strip()


def _render_html_evidence_mappings(finding: HeaderFinding) -> str:
    if not finding.evidence_mappings:
        return "<p>No direct evidence mapping claimed.</p>"
    items = "".join(
        "<li>"
        f"<strong>{escape(mapping.label)}</strong>"
        f"<span>{escape(mapping.rationale)}</span>"
        f"<small>Confidence: {escape(mapping.confidence.title())}</small>"
        f"<small>Limitation: {escape(mapping.limitations)}</small>"
        "</li>"
        for mapping in finding.evidence_mappings
    )
    return f'<ul class="mapping-list">{items}</ul>'
