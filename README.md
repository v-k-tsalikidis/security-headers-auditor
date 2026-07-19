# Security Headers Auditor

[![CI](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB.svg)](pyproject.toml)

Context-aware, read-only Python CLI for reviewing HTTP security headers as an
authenticated web application, API response, or public brochure site.

Security Headers Auditor avoids the universal checklist model. It records why a
response profile was selected, scores only controls applicable to that profile,
identifies weak values, and preserves a versioned evidence trail to standards and
research. Version 0.5 adds an optional local workspace over the same Python
engine; it does not create a second scanner or send targets to a hosted service.
Version 0.6 adds offline profile definitions, bounded route comparison, and
deeper CSP parsing. Continuous assurance adds policy thresholds, approved
baselines, regression detection, and CI-native outputs without turning evidence
mappings into certification claims.

## Why Context Matters

A JSON API should not receive the same browser-document penalties as an authenticated
HTML application. A header can also be present and still be weak. Version 0.4 treats
applicability, configuration quality, assurance policy, regression state, and
compliance-supporting evidence as separate concerns.

The result is a transparent engineering assessment:

- profile-specific 100-point scoring for `app`, `api`, and `brochure`;
- conservative auto-detection with confidence and decision evidence;
- explicit `--profile` override when the operator knows the endpoint purpose;
- partial credit for weak or incomplete values;
- contextual and disclosure observations outside the score;
- reporting endpoint syntax and CSP reporting-linkage analysis;
- response-level COOP/COEP cross-origin isolation readiness analysis;
- versioned OWASP ASVS 5.0.0 and NIST SP 800-53 evidence mappings;
- mappings explicitly labelled as supporting evidence, never compliance proof;
- JSON policy-as-code and deterministic approved baselines;
- score, profile, and control-state regression detection;
- SARIF 2.1.0 and JUnit XML outputs for CI systems;
- deterministic machine-readable profile definitions for offline CI and review;
- Markdown, JSON, and offline self-contained HTML reports;
- a loopback-only workspace for authorized inventories, results, and reviewed
  baseline approval;
- deterministic tests with no remote-site dependency.

## Profiles

| Profile | Intended response | Scored emphasis |
| --- | --- | --- |
| `app` | Authenticated or stateful HTML application | Transport, CSP, MIME, framing, privacy, permissions, COOP, and CORP |
| `api` | JSON, GraphQL, or XML response | Transport and authoritative media typing |
| `brochure` | Public HTML content with limited authenticated state | Transport, CSP, MIME, framing, privacy, and permissions |

Auto-detection is deliberately conservative. It cannot prove business purpose.
Use a manual profile for controlled assessments.

## Profile Definitions For CI And Review

Export the complete, canonical profile configuration without making an HTTP
request. The output contains profile applicability and weights, rule rationale,
standards, source citations, and explicitly limited supporting-evidence
mappings—never a target, response, raw header, or assessment result.

```bash
security-headers-auditor \
  --export-profile-definitions artifacts/profile-definitions.json
```

The export is stable and timestamp-free for meaningful source-control and CI
diffs. Its [JSON Schema](docs/schemas/profile-definitions.schema.json) is
versioned; it is a tool-configuration document, not a compliance attestation or
proof of a live endpoint's security.

## Controlled Route Comparison

Use a route comparison when one authorized origin has several known, important
routes and you need to see whether like-for-like response profiles have
different scored-control states. The manifest contains exactly one origin and
2–25 explicit, query-free paths; it never crawls, discovers routes, or follows
cross-origin redirects.

```bash
security-headers-auditor \
  --route-comparison examples/route-comparison.json \
  --format json \
  --output reports/portal-route-comparison.json
```

Each route declares `app`, `api`, or `brochure` explicitly. A difference is a
review signal, not a vulnerability, policy failure, compliance decision, or a
replacement for an approved continuous-assurance baseline. The compact output
omits raw response-header values; use individual reports only in an authorized,
controlled evidence store. See the
[manifest schema](docs/schemas/route-comparison.schema.json) and
[decision record](docs/adr/0005-controlled-route-comparison.md).

## CSP Parsing Depth

The CSP evaluator now retains the first duplicate directive according to CSP
parser semantics, preserves nonce/hash token case, distinguishes valid from
invalid nonce/hash syntax, and flags `data:` in the effective script source
list. Multiple serialized policies and malformed tokens become review signals;
the tool does not try to emulate the browser's complete policy intersection.

This changes response-score semantics. v0.6 uses methodology `0.5.0`, so a
v0.4 policy or baseline is deliberately rejected until it is reviewed and
re-baselined. This is a safety boundary, not an automatic migration. CSP output
still cannot prove nonce lifecycle, browser enforcement, document-resource
coverage, application compatibility, or bypass resistance. See
[ADR 0006](docs/adr/0006-csp-parser-and-methodology-version.md).

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

Assess reporting and cross-origin isolation readiness without changing the profile
score:

```bash
security-headers-auditor https://portal.example.com \
  --profile app \
  --reporting-readiness required \
  --cross-origin-isolation recommended \
  --format html \
  --output reports/portal-assurance.html
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

## Local Workspace

The optional workspace is a local interface to the same audit and assurance
engine. It starts only on `127.0.0.1`, stores data locally, and has no accounts,
telemetry, analytics, cloud synchronization, or third-party runtime assets.

```bash
security-headers-auditor workspace
```

The command opens a local browser page. Create a workspace, add only authorized
targets with explicit response profiles, then choose **Run** or **Run assurance**.
An import is previewed and requires explicit confirmation; importing never starts
an assessment. Use `Ctrl+C` in the terminal to stop the local service.

Private, loopback, link-local, and reserved addresses are blocked by default.
For an explicitly authorized internal or test system, opt in only for that
workspace session:

```bash
security-headers-auditor workspace --allow-private-targets
```

See the [v0.5 workspace tutorial](docs/V0.5_WORKSPACE_TUTORIAL.md) and its
[controlled screenshots](docs/images/README.md).

## Continuous Assurance

Continuous assurance uses a version-pinned JSON policy. Every target has a stable
identifier and an explicit response profile by default. Copy
[`examples/audit-policy.json`](examples/audit-policy.json), replace the example
targets with systems inside the authorized scope, and review every threshold.

Create an initial candidate baseline:

```bash
security-headers-auditor \
  --policy audit-policy.json \
  --write-baseline assurance-baseline.json \
  --format json \
  --output reports/assurance-initial.json
```

Review and approve the baseline diff before committing it. Subsequent CI runs can
detect score, profile, and control-status regressions:

```bash
security-headers-auditor \
  --policy audit-policy.json \
  --baseline assurance-baseline.json \
  --format sarif \
  --output reports/assurance.sarif
```

JUnit output is available with `--format junit`. Exit codes are stable:

| Code | Meaning |
| ---: | --- |
| `0` | Policy passed and no regression was detected |
| `1` | Policy violation or approved-baseline regression |
| `2` | Invalid configuration, incompatible baseline, or operational audit failure |

A baseline is an explicitly approved configuration state, not a waiver. Methodology
or evidence-mapping version changes require review and a new baseline.

## Output Model

Every successful result contains:

- requested and selected profile;
- detection confidence and evidence;
- score and summary;
- profile-scored findings with points and applicability;
- reporting readiness and cross-origin isolation assurance controls;
- contextual findings;
- information-disclosure observations;
- versioned evidence mappings with rationale and limitations;
- standards and research citations.

Route-comparison output instead minimizes evidence to route identifiers and
paths, declared profile, redacted final URL, status, score, scored-control state,
review-only variance, and operational errors. It intentionally excludes raw
header values.

The HTML report is one portable file with no JavaScript, external fonts, analytics,
or remote style assets. It uses semantic HTML, native disclosure controls, keyboard
focus, non-color status labels, responsive reflow, and print styles.

## Methodology

The implementation is governed by:

- [v0.4 Methodology Specification](docs/V0.4_METHODOLOGY_SPECIFICATION.md)
- [v0.5 Workspace Methodology Specification](docs/V0.5_METHODOLOGY_SPECIFICATION.md)
- [v0.6 Methodology and Delivery Specification](docs/V0.6_METHODOLOGY_SPECIFICATION.md)
- [v0.5 Workspace Tutorial](docs/V0.5_WORKSPACE_TUTORIAL.md)
- [Continuous Assurance Guide](docs/CONTINUOUS_ASSURANCE.md)
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
pnpm --dir frontend test --run
pnpm --dir frontend build
```

The suite covers API, authenticated application, brochure, hostile evidence,
reporting endpoint parsing, CSP reporting linkage, cross-origin isolation,
policy validation, deterministic baselines, regressions, SARIF, JUnit, manual
override, redirect boundaries, redaction, escaping, and offline report constraints.

## Release Discipline

- [v0.6.1 release gate](docs/RELEASE_GATE_V0.6.1.md)
- [v0.6.1 release notes](docs/releases/v0.6.1.md)
- [v0.6.0 release gate](docs/RELEASE_GATE_V0.6.md)
- [v0.6.0 release notes](docs/releases/v0.6.0.md)
- [v0.4.0 release gate](docs/RELEASE_GATE_V0.4.md)
- [v0.4.0 release notes](docs/releases/v0.4.0.md)
- [v0.5.0 release gate](docs/RELEASE_GATE_V0.5.md)
- [v0.5.0 release notes](docs/releases/v0.5.0.md)
- [v0.3.0 release gate](docs/RELEASE_GATE_V0.3.md)
- [v0.3.0 release notes](docs/releases/v0.3.0.md)
- [v0.2.0 release notes](docs/releases/v0.2.0.md)

A release is not labelled complete until automated tests, the Python CI matrix,
desktop/mobile browser QA, accessibility checks, documentation, and the intended
repository diff have verified evidence. A tag-triggered release is configured to
build the wheel and source distribution, publish SHA-256 checksums, and record a
GitHub artifact provenance attestation before publication.

## Authorized Use

The tool performs a `HEAD` request chain. It uses one `GET` compatibility fallback
only when the server returns `405` or `501` for `HEAD`. Cross-origin redirects are
blocked unless the operator explicitly authorizes them. It does not crawl,
authenticate, fuzz, exploit, brute-force, or bypass controls.

Use it only on systems you own, administer, or are explicitly authorized to assess.
See [DISCLAIMER.md](DISCLAIMER.md).

## Roadmap

- [x] Add optional machine-readable profile-definition export.
- [x] Add controlled multi-response assessment for route-level profile comparison.
- [x] Add CSP parsing depth without claiming full browser-policy validation.
