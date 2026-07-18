# Security Headers Auditor

Risk-aware, public-safe Python CLI for reviewing common HTTP security headers and producing readable Markdown or JSON reports.

This project is part of my cybersecurity portfolio. It connects practical web security hygiene, lightweight assessment logic, and clear reporting: what was checked, why it matters, which signals are missing or weak, and what should be reviewed next.

## Why It Matters

HTTP security headers are not a complete security program, but they are a useful baseline signal. They help reduce exposure to common web risks such as clickjacking, MIME sniffing, insecure transport, overly broad browser permissions, and weak content isolation.

The goal of this project is to provide a small tool that remains understandable while avoiding the common weakness of simple "present/missing" header checkers. A header can exist and still be weak. Some headers are baseline controls; others are contextual and may not belong on every endpoint.

## What Makes It Different

- Uses a weighted baseline score instead of a flat header count.
- Separates baseline controls from contextual checks and information-disclosure observations.
- Flags weak values, not only missing headers.
- Keeps the scan read-only: no crawling, exploitation, brute forcing, or intrusive testing.
- Produces reports that explain the finding and the recommended next review step.
- Uses public guidance from OWASP, MDN, Mozilla HTTP Observatory, and web.dev as the initial methodology base.

## Checked Headers

| Area | Header | Purpose |
| --- | --- | --- |
| Baseline | `Strict-Transport-Security` | Reduces downgrade and protocol-stripping exposure after first HTTPS use. |
| Baseline | `Content-Security-Policy` | Limits content injection and cross-site scripting blast radius. |
| Baseline | `X-Content-Type-Options` | Prevents MIME sniffing. |
| Baseline | `X-Frame-Options` | Provides a legacy clickjacking control. |
| Baseline | `Referrer-Policy` | Limits URL and query leakage through the `Referer` header. |
| Baseline | `Permissions-Policy` | Restricts powerful browser features. |
| Baseline | `Cross-Origin-Opener-Policy` | Reduces cross-origin window interaction risk. |
| Baseline | `Cross-Origin-Resource-Policy` | Controls whether other origins can read a response as a resource. |
| Contextual | `Cross-Origin-Embedder-Policy`, `Clear-Site-Data`, `Cache-Control`, `X-DNS-Prefetch-Control`, `X-Permitted-Cross-Domain-Policies` | Reported separately because they depend on endpoint type and compatibility. |
| Disclosure | `Server`, `X-Powered-By`, selected framework/version headers | Reported as information-disclosure observations. |

See [docs/METHODOLOGY.md](docs/METHODOLOGY.md) for the scoring model and references.

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Audit one target:

```bash
security-headers-auditor https://example.com --format markdown
```

Audit multiple targets from a file:

```bash
security-headers-auditor --input-file examples/targets.txt --format markdown --output reports/security-headers-report.md
```

Generate JSON:

```bash
security-headers-auditor https://example.com --format json --output reports/example-report.json
```

## Example Output

```text
Target: https://example.com
Score: 35/100
Status: Needs Review

Baseline findings include status, severity, points, evidence, and recommendation.
Contextual and information-disclosure findings are separated from the score.
```

See [examples/sample-report.md](examples/sample-report.md) for a deterministic sample report.

## Development

Run the unit tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Project Documentation

- [Differentiation brief](docs/DIFFERENTIATION_BRIEF.md)
- [Methodology](docs/METHODOLOGY.md)
- [Disclaimer](DISCLAIMER.md)

## Public Safety

This is a read-only educational tool. It checks HTTP response headers for targets explicitly provided by the user. It does not exploit, brute-force, crawl, or perform intrusive scanning.

See [DISCLAIMER.md](DISCLAIMER.md).

## Roadmap

- Add optional HTML report output with a restrained, professional design.
- Add CSV output for larger website lists.
- Add optional NIST CSF 2.0 / OWASP ASVS mapping notes.
- Add response classification profiles: brochure site, authenticated app, API endpoint.
- Add GitHub Actions CI and release artifacts.
- Add screenshots of sample reports.
