# v0.6.0 Release Gate

## Release Classification

Current classification: **in development; not published**.

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

## Functional And Regression Evidence

- [x] Deterministic profile-export, route-comparison, CSP-parser, policy, baseline,
  audit, workspace, and hostile-input tests pass locally.
- [x] Route-comparison CLI completes against deterministic loopback fixtures.
- [x] Audit and reporting-linkage code share first-duplicate CSP parsing behavior.
- [x] Current policy and baseline examples validate against committed schemas.
- [ ] Full Python suite rerun after final release documentation and packaging changes.
- [ ] Frontend test and production build rerun after final release documentation and packaging changes.
- [ ] Built wheel and source distribution contain new modules, schemas, docs, and
  workspace static assets; clean offline installation passes.

## Publication Evidence

- [ ] GitHub Actions supported Python/Node CI is green for the final commit.
- [ ] Release workflow builds distributions, runs the full suite, publishes
  SHA-256 checksums, and records provenance for the final tagged commit.
- [ ] Published artifacts are independently checked against their checksums and
  provenance before GitHub Release creation.
- [ ] README, methodology, ADRs, schemas, examples, release notes, and gate
  match the final behavior.
- [ ] Repository diff contains no secrets, databases, reports, caches, or
  unrelated files.

Any non-applicable item requires a written rationale. Historical v0.5 evidence
does not satisfy v0.6 release gates.
