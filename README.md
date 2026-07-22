# Response Ledger

### Security Headers Auditor

<p align="center">
  <img src="docs/images/response-ledger-wordmark.png" alt="Response Ledger wordmark" width="620" />
</p>

[![CI](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB.svg)](pyproject.toml)

**Response Ledger** is the public identity of **Security Headers Auditor**, an
independent security-engineering project by Vasileios Tsalikidis. It is a
context-aware, read-only Python tool for reviewing HTTP security headers on an
application response, API response, or public brochure site.

> **Response context. Reviewable evidence.**

The identity does not rename the Python package, command-line interface, or
repository. Those remain `security-headers-auditor` so existing use and release
evidence stay stable.

> **Authorized use:** Run this local, low-impact tool only on systems you own,
> administer, or are explicitly authorized to assess. It does not crawl,
> authenticate, fuzz, exploit, brute-force, or bypass access controls.

## Why This Instead Of A Generic Header Checker?

Most header checkers answer whether a familiar header is present. This project
is designed for the engineering question that follows: **is the observed
response configuration appropriate for this kind of endpoint, and can the
result be reviewed over time?**

- It evaluates `app`, `api`, and `brochure` responses differently, with a
  conservative auto-detection record and an explicit operator override.
- It assesses selected configuration quality, including weak and incomplete
  values, rather than treating every present header as equally useful.
- It keeps scored controls, contextual observations, disclosure signals, and
  framework evidence separate, so a score is not misread as a vulnerability
  count or compliance decision.
- It supports policy-as-code, approved baselines, route-level review, compact
  evidence capsules, and CI outputs for change-control work.
- It remains local-first and bounded: the operator supplies the targets, the
  request model is read-only, and stored workspace history is data-minimized.

These are design choices for a narrower, more reviewable assessment—not a
claim that the tool proves a target secure or replaces application testing. See
the [product positioning](docs/PRODUCT_POSITIONING.md) and
[responsible-use boundary](docs/RESPONSIBLE_USE.md).

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
- a bounded local audit-session history with timestamps and collision-resistant
  report filenames;
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

## Controlled Route Assurance

Route comparison can also detect drift against an explicitly reviewed baseline.
This stays separate from the target-policy baseline: it covers exactly one
same-origin, 2–25 route manifest and never discovers routes.

Create a candidate from a complete run, review it through normal change control,
then store it as the approved baseline in a controlled location:

```bash
security-headers-auditor \
  --route-comparison examples/route-comparison.json \
  --write-route-baseline candidates/portal-routes.json \
  --format json \
  --output reports/portal-route-candidate.json
```

An existing candidate path is never overwritten. After review, enforce the
baseline in CI:

```bash
security-headers-auditor \
  --route-comparison examples/route-comparison.json \
  --route-baseline approved/portal-routes.json \
  --format json \
  --output reports/portal-route-assurance.json
```

Scope, methodology, mapping-set, route ID, path, or declared-profile changes
are incompatible until reviewed and re-baselined. A route baseline is a drift
comparison state, not a waiver, vulnerability verdict, compliance decision, or
proof of browser behaviour. See the [baseline schema](docs/schemas/route-assurance-baseline.schema.json)
and [ADR 0007](docs/adr/0007-controlled-route-assurance.md).

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

The workspace keeps the latest 50 audit-session summaries in **History**. Each
entry records its UTC completion time, scope, target score, outcome, and audit
ID. Detailed header values remain only in the active run and any report you
explicitly download. Report downloads include the scope, UTC timestamp, and
audit ID in the filename, so successive audits do not overwrite one another.

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

## Offline Review Evidence Capsule

For a controlled review, first produce the deliberately data-minimized
`review-json` result from the exact assurance run and baseline, then package it
without triggering another assessment:

```bash
security-headers-auditor --policy audit-policy.json \
  --baseline assurance-baseline.json \
  --format review-json --output reports/assurance-review.json

security-headers-auditor --create-evidence-capsule reports/review.shac \
  --capsule-policy audit-policy.json \
  --capsule-assessment reports/assurance-review.json \
  --capsule-baseline assurance-baseline.json

security-headers-auditor --verify-evidence-capsule reports/review.shac
```

The capsule is deterministic and verified in place; it is never extracted and
does not make a target or third-party network request. It retains the explicit
review scope because that is necessary to bind an outcome, but excludes raw
response-header values, URLs from the compact assessment, response metadata,
diagnostic prose, credentials, query strings, and fragments. It supplies
integrity evidence only when the reviewer compares its printed SHA-256 with a
trusted expected digest; it does not authenticate an author or establish that a
target is secure. See the [v0.8 capsule specification](docs/V0.8_METHODOLOGY_SPECIFICATION.md).

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
- [v0.7 Controlled Route Assurance Specification](docs/V0.7_METHODOLOGY_SPECIFICATION.md)
- [v0.8 Portable Review Evidence Capsule Specification](docs/V0.8_METHODOLOGY_SPECIFICATION.md)
- [v0.9 Workspace Audit History Specification](docs/V0.9_WORKSPACE_AUDIT_HISTORY.md)
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
- [v0.7 release gate](docs/RELEASE_GATE_V0.7.md)
- [v0.7 release notes](docs/releases/v0.7.0.md)
- [v0.8 release gate](docs/RELEASE_GATE_V0.8.md)
- [v0.8 release notes](docs/releases/v0.8.0.md)
- [v0.9 release candidate notes](docs/releases/v0.9.0.md)
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
- [x] v0.7: verified release of data-minimized route baselines for controlled
  route-level drift assurance.
- [x] v0.8: verified tag-triggered release of an offline-verifiable, portable
  review-evidence capsule.
- [x] v0.9: verified release of bounded, local audit-session history and
  timestamped report exports.

The detailed post-v0.6.1 scope, safety boundaries, and release gates are in the
[product roadmap](docs/ROADMAP.md).
