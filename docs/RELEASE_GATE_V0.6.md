# v0.6.0 Release Gate

## Release Classification

Current classification: **stable; v0.6.0 published on 2026-07-19**.

This gate is evidence-driven. No v0.6.0 tag, GitHub Release, announcement, or
claim of release completeness is permitted until every applicable item is
checked and recorded.

## Scope And Methodology

- [x] Machine-readable profile-definition export is deterministic, schema-bound,
  network-free, and documentation-complete.
- [x] Route comparison is explicit, same-origin, bounded, non-crawling, and
  review-only.
- [x] CSP parser retains first duplicate directives, preserves nonce/hash token
  case, bounds parsing, and labels multi-policy ambiguity.
- [x] CSP score semantic change is documented in ADR 0006.
- [x] Tool version is `0.6.0`; methodology version is `0.5.0`.
- [x] v0.4 policies and baselines are rejected and require reviewed re-baselining.

## Security, Privacy, And Claims

- [x] Profile export contains no target or response data and does no network I/O.
- [x] Route comparison requires 2–25 unique, query-free paths on one exact origin.
- [x] Route summaries omit raw response-header values.
- [x] Existing redirect, query-redaction, authorization, and loopback workspace
  bounds remain regression-tested.
- [x] CSP parser limits analysis to 16 KiB and does not claim browser-equivalent
  enforcement, nonce lifecycle verification, route coverage, or bypass resistance.
- [x] Framework mappings remain supporting evidence only; no compliance,
  certification, endorsement, or effectiveness claim was added.
- [x] Dependency and license revalidation records no new runtime, test, frontend,
  lockfile, or build-tool dependency in v0.6.

## Functional And Regression Evidence

- [x] Deterministic profile-export, route-comparison, CSP-parser, policy, baseline,
  audit, workspace, and hostile-input tests pass locally.
- [x] Route-comparison CLI completes against deterministic loopback fixtures.
- [x] Audit and reporting-linkage code share first-duplicate CSP parsing behavior.
- [x] Current policy and baseline examples validate against committed schemas.
- [x] Full Python suite rerun after final release documentation and packaging changes.
- [x] Frontend test and production build rerun after final release documentation and packaging changes.
- [x] Built wheel contains the v0.6 modules, compliance-evidence data, license
  notices, and workspace static assets; source distribution contains the release
  source and tests; clean offline installation passes.

## Publication Evidence

- [x] GitHub Actions supported Python/Node CI is green for the final commit.
- [x] Release workflow builds distributions, runs the full suite, publishes
  SHA-256 checksums, and records provenance for the final tagged commit.
- [x] Pre-tag release artifacts are independently checked against their checksums
  and provenance before GitHub Release creation.
- [x] README, methodology, ADRs, schemas, examples, release notes, and gate
  match the final behavior.
- [x] Repository diff contains no secrets, databases, reports, caches, or
  unrelated files.

## Pre-Tag Evidence

- Local verification on 2026-07-19: 135 Python tests passed; 6 frontend tests,
  type check, production build, and packaged-asset synchronization passed; the
  deterministic CI assurance fixture produced matching candidate baseline, JSON,
  SARIF, and JUnit outputs. A clean Git archive build passed wheel/source
  contents, offline-install, profile-export, and `.DS_Store` checks.
- GitHub [CI #24](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29698807661)
  passed for final pre-tag commit `a3092bd`.
- Manually dispatched [Release Artifacts #4](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29698926661)
  passed for `a3092bd`; its publish job was skipped by design because no tag
  existed. The downloaded artifact matched GitHub's published artifact digest
  `d3b4a1b72bd8fea9c8211ac14cd67dea677b4bc0bd05730defbe08a6553f6523`; its
  wheel and source archive matched the enclosed `SHA256SUMS` manifest.
  [Attestation #36056554](https://github.com/v-k-tsalikidis/security-headers-auditor/attestations/36056554)
  records provenance for the wheel, source archive, and checksum manifest.

The tag-triggered item was deliberately left open in the tagged source until the
annotated `v0.6.0` tag had passed CI and its independent artifacts and
provenance were verified. This `main`-branch record captures that post-tag
evidence without rewriting the published tag.

## Tag And Publication Evidence

- Annotated tag `v0.6.0` points to `075e4b5`. GitHub [CI #26](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29699075875)
  passed for that tag.
- Tag-triggered [Release Artifacts #5](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29699075870)
  passed: package and publish jobs both succeeded, and the workflow created the
  public [v0.6.0 GitHub Release](https://github.com/v-k-tsalikidis/security-headers-auditor/releases/tag/v0.6.0).
- The downloaded tag artifact matched GitHub's published artifact digest
  `33df5f7bc2d7ee27d81526f8dae85f7205d6d438ea6929985c5e995d4f05f873`, and
  its wheel and source archive matched the enclosed `SHA256SUMS` manifest.
  [Attestation #36056875](https://github.com/v-k-tsalikidis/security-headers-auditor/attestations/36056875)
  records tag-scoped provenance for the wheel, source archive, and checksum
  manifest.
- GitHub emitted runner notices that several immutable third-party Action pins
  still declare a Node 20 action runtime and were forced by GitHub onto Node 24.
  Both package and publish jobs passed, and the independently verified artifacts
  are unaffected. Updating an immutable action pin is a separately reviewed
  supply-chain maintenance change; it was not silently bundled into this release.

Any non-applicable item requires a written rationale. Historical v0.5 evidence
does not satisfy v0.6 release gates.
