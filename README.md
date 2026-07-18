# Security Headers Auditor

Small, public-safe Python tool for checking common HTTP security headers and producing a readable report.

This project is part of my cybersecurity portfolio. It connects practical web security hygiene with clear, recruiter-readable reporting: what was checked, why it matters, what is missing, and what should be reviewed next.

## Why It Matters

HTTP security headers are not a complete security program, but they are a useful baseline signal. They help reduce exposure to common web risks such as clickjacking, MIME sniffing, insecure transport, overly broad browser permissions, and weak content isolation.

The goal of this project is simple:

- check a small set of user-provided websites;
- identify missing or weak security header signals;
- generate a concise Markdown or JSON report;
- keep the implementation lightweight, transparent, and easy to run.

## Checked Headers

| Header | Purpose |
| --- | --- |
| `Strict-Transport-Security` | Encourages HTTPS-only access after first successful connection. |
| `Content-Security-Policy` | Helps reduce cross-site scripting and content injection risk. |
| `X-Content-Type-Options` | Helps prevent MIME sniffing. |
| `X-Frame-Options` | Helps reduce clickjacking risk. |
| `Referrer-Policy` | Controls how much referrer information is shared. |
| `Permissions-Policy` | Restricts browser features available to the page. |
| `Cross-Origin-Opener-Policy` | Supports cross-origin isolation and window separation. |

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
Score: 43/100
Status: Needs Review

Present:
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- Referrer-Policy: no-referrer

Missing:
- Strict-Transport-Security
- Content-Security-Policy
- Permissions-Policy
- Cross-Origin-Opener-Policy
```

## Public Safety

This is a read-only educational tool. It checks HTTP response headers for targets explicitly provided by the user. It does not exploit, brute-force, crawl, or perform intrusive scanning.

See [DISCLAIMER.md](DISCLAIMER.md).

## Roadmap

- Add HTML report output.
- Add CSV output for larger website lists.
- Add basic severity weighting.
- Add optional NIST CSF 2.0 mapping notes.
- Add screenshots of sample reports.

