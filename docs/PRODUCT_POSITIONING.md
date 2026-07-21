# Product Positioning

## Identity

**Response Ledger**

Security Headers Auditor · Independent security-engineering project by
**Vasileios Tsalikidis**

**Positioning statement:** A local-first, context-aware HTTP response-header
assessment tool for engineers who need a reviewable configuration decision—not
just a generic grade.

**Tagline:** *Response context. Reviewable evidence.*

Response Ledger is the public product identity. The repository, Python package,
and command-line interface continue to use **Security Headers Auditor** and
`security-headers-auditor`; this preserves technical continuity and published
release evidence.

The product intentionally looks and behaves like an engineering instrument:
quiet, precise, inspectable, and conservative about what it claims.

## What Is Different

| Engineering choice | Practical value |
| --- | --- |
| Context before score | `app`, `api`, and `brochure` profiles avoid applying browser-document expectations blindly to every response. Conservative auto-detection records its basis; the operator can override it. |
| Quality, not mere presence | Selected controls distinguish robust, weak, and incomplete values instead of rewarding a header simply for existing. |
| Reviewable change control | Policy-as-code, explicit baseline approval, route review, regression detection, timestamped reports, and compact evidence capsules support comparison over time. |
| Evidence with boundaries | Versioned OWASP and NIST mappings include rationale and limitations; scored gaps, contextual observations, and disclosure signals remain separate. |
| Local-first, bounded operation | No hosted target collection, telemetry, accounts, crawling, authentication, or active probing. Workspace data is local and history is compact. |
| Reproducible delivery | Deterministic fixtures, unit and frontend tests, CI-native JSON/SARIF/JUnit output, package checks, checksums, and provenance-aware releases make the tool easier to inspect and trust. |

## Why A Team Might Choose It

Choose Response Ledger when the goal is to make a defensible,
repeatable decision about a known response configuration: before a release,
after a CDN or framework change, during a configuration review, or in CI.

It is deliberately not positioned as a replacement for a full web application
test, a browser-runtime CSP validator, a hosted scanner, or a compliance
platform. The value is precision within a narrow scope: an explicit request
boundary, profile-aware scoring, evidence that can be reviewed, and change
signals that are not silently reinterpreted.

## Public Comparison Boundary

The project does not claim universal superiority over other header tools.
Generic checkers, hosted scanners, and response-snapshot analyzers solve useful
problems. This project makes a distinct set of trade-offs: it favors
operator-supplied scope, local execution, context-aware assessment, and
reviewable longitudinal evidence over broad discovery, hosted convenience, or
a one-size-fits-all grade.

## Visual System

The identity uses a typographic wordmark rather than a literal cyber-security
symbol. It avoids shields, padlocks, terminals, "hacker" imagery, and decorative
icon fields; the product’s clarity should come from its evidence model and
editorial hierarchy, not from a visual cliché.

| Element | Choice |
| --- | --- |
| Base | Warm paper `#fffefb` and quiet surface `#f6f5f0` |
| Ink | Graphite `#202426` |
| Signature | Deep muted teal `#0d5c63` |
| Status | Desaturated green, ochre, rose, and blue—always paired with text labels |
| Typography | System sans-serif for reading; tabular/system mono only for identifiers and evidence values |
| Layout | Editorial spacing, fine borders, no gradients, glow, dark cyber backgrounds, decorative icon fields, or visual noise |

## Identity Use

The primary mark is the typographic **Response Ledger** wordmark. “Response” is
graphite and “Ledger” is deep teal, paired with a restrained copper rule. The
mark represents a recorded, reviewable response configuration rather than a
generic security symbol.

Use **Response Ledger / Security Headers Auditor** when both the public
identity and the technical implementation need to be clear. Use the full
technical name for installation, package metadata, CLI commands, schemas,
versioning, and release evidence.

The identity should always be accompanied by evidence-backed language. It can
say *local-first*, *read-only*, *context-aware*, and *reviewable* because those
behaviours are implemented and tested. It must not imply certification, complete
browser-policy validation, continuous target monitoring, or proof that an
endpoint is secure.
