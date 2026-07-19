# Security Headers Auditor

[![CI](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB.svg)](pyproject.toml)

Context-aware, read-only Python CLI for reviewing HTTP security headers as an
authenticated web application, API response, or public brochure site.

Security Headers Auditor avoids the universal checklist model. It records why a
response profile was selected, scores only controls applicable to that profile,
identifies weak values, and preserves an evidence trail to standards and research.

## Why Context Matters

A JSON API should not receive the same browser-document penalties as an authenticated
HTML application. A header can also be present and still be weak. Version 0.3 treats
applicability, configuration quality, and evidence as separate concerns.

The result is a transparent engineering assessment:

- profile-specific 100-point scoring for `app`, `api`, and `brochure`;
- conservative auto-detection with confidence and decision evidence;
- explicit `--profile` override when the operator knows the endpoint purpose;
- partial credit for weak or incomplete values;
- contextual and disclosure observations outside the score;
- version-pinned OWASP ASVS 5.0.0 mappings and primary specifications;
- NIST relationships clearly labelled as control-informed, not compliance proof;
- Markdown, JSON, and offline self-contained HTML reports;
- deterministic tests with no remote-site dependency.

## Profiles

| Profile | Intended response | Scored emphasis |
| --- | --- | --- |
| `app` | Authenticated or stateful HTML application | Transport, CSP, MIME, framing, privacy, permissions, COOP, and CORP |
| `api` | JSON, GraphQL, or XML response | Transport and authoritative media typing |
| `brochure` | Public HTML content with limited authenticated state | Transport, CSP, MIME, framing, privacy, and permissions |

Auto-detection is deliberately conservative. It cannot prove business purpose.
Use a manual profile for controlled assessments.

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Audit one response with conservative profile detection:

```bash
security-headers-auditor https://example.com
```

Audit a known API and produce JSON:

```bash
security-headers-auditor https://api.example.com/status \
  --profile api \
  --format json \
  --output reports/api-report.json
```

Generate the offline HTML report:

```bash
security-headers-auditor https://portal.example.com \
  --profile app \
  --format html \
  --output reports/portal-report.html
```

Audit a controlled list:

```bash
security-headers-auditor \
  --input-file examples/targets.txt \
  --profile brochure \
  --format markdown \
  --output reports/sites.md
```

URL query strings and fragments are redacted in reports by default. Retain them
only when the output is controlled:

```bash
security-headers-auditor "https://example.com/path?case=public" --include-query
```

Redirects that leave the original origin are blocked by default. A same-host
HTTP-to-HTTPS upgrade remains allowed. Follow an external redirect only when its
destination is inside the authorized scope:

```bash
security-headers-auditor https://example.com \
  --allow-cross-origin-redirects
```

## Output Model

Every successful result contains:

- requested and selected profile;
- detection confidence and evidence;
- score and summary;
- profile-scored findings with points and applicability;
- contextual findings;
- information-disclosure observations;
- standards and research citations.

The HTML report is one portable file with no JavaScript, external fonts, analytics,
or remote style assets. It uses semantic HTML, native disclosure controls, keyboard
focus, non-color status labels, responsive reflow, and print styles.

## Methodology

The implementation is governed by:

- [v0.3 Methodology Specification](docs/V0.3_METHODOLOGY_SPECIFICATION.md)
- [Citation Manifest](docs/CITATION_MANIFEST.md)
- [Methodology overview](docs/METHODOLOGY.md)
- [Privacy, Accessibility, and Authorization](docs/PRIVACY_ACCESSIBILITY_AUTHORIZATION.md)
- [Differentiation brief](docs/DIFFERENTIATION_BRIEF.md)

The score expresses alignment with the selected response profile. It is not proof
that an application is secure, a vulnerability count, or a compliance decision.

## Development

Run the deterministic suite:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The 32-test suite covers API, authenticated application, brochure, hostile evidence,
manual override, redirect boundaries, method fallback, redaction, HTML escaping,
and offline report constraints.

## Release Discipline

- [v0.3.0 release gate](docs/RELEASE_GATE_V0.3.md)
- [v0.3.0 release notes](docs/releases/v0.3.0.md)
- [v0.2.0 release notes](docs/releases/v0.2.0.md)

A release is not labelled complete until automated tests, the Python CI matrix,
desktop/mobile browser QA, accessibility checks, documentation, and the intended
repository diff have verified evidence.

## Authorized Use

The tool performs a `HEAD` request chain. It uses one `GET` compatibility fallback
only when the server returns `405` or `501` for `HEAD`. Cross-origin redirects are
blocked unless the operator explicitly authorizes them. It does not crawl,
authenticate, fuzz, exploit, brute-force, or bypass controls.

Use it only on systems you own, administer, or are explicitly authorized to assess.
See [DISCLAIMER.md](DISCLAIMER.md).

## Roadmap

- Add optional machine-readable profile-definition export.
- Add controlled multi-response assessment for route-level profile comparison.
- Add CSP parsing depth without claiming full browser-policy validation.
- Add signed release artifacts after the v0.3 release gate is complete.
