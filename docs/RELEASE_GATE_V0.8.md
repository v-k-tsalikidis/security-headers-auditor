# v0.8 Release Gate

## Release Classification

Current classification: **release candidate; not tagged or published**.

No `v0.8.0` tag, GitHub Release, announcement, or completeness claim is
permitted until each applicable item below has reproducible evidence.

## Scope And Methodology

- [x] Scope is limited to a local deterministic capsule of an existing compact
  policy or route assessment; no target request occurs during creation or
  verification.
- [x] Methodology (`0.5.0`), profiles, score semantics, CSP parser, policy
  semantics, and framework mappings are unchanged.
- [x] The capsule carries a self-contained JSON manifest schema and enforces a
  stricter allowlisted runtime contract without remote schema retrieval.
- [x] Capsule creation refuses an existing output path and no operation extracts
  archive content.

## Security, Privacy, And Claims

- [x] Compact review assessments omit raw response-header values, URLs,
  response metadata, diagnostic prose, credentials, cookies, query strings, and
  fragments.
- [x] Policy scope rejects query-bearing URLs, fragments, credentials,
  `include_query`, and cross-origin redirects; route scope reuses the explicit
  bounded same-origin contract.
- [x] Verification rejects symlink/non-regular inputs, oversized inputs,
  duplicate/missing/additional/encrypted/compressed ZIP entries, non-canonical
  JSON, digest mismatches, and incompatible scope/baseline/version bindings.
- [x] The capsule is integrity evidence for review, not a signature, identity
  statement, security pass, compliance decision, vulnerability finding, or
  browser runtime validation.
- [x] No dependency, hosted service, telemetry, authentication, crawling,
  fuzzing, exploitation, or automatic approval is added.

## Functional And Regression Evidence

- [x] Dedicated tests cover deterministic policy and route capsules, optional
  baseline binding, full offline verification, raw-header omission, manifest
  tampering, duplicate ZIP entries, query-bearing scope rejection, broad-report
  rejection, and CLI proof that creation does not call the audit engine.
- [ ] Full Python suite, compile check, deterministic command-line fixture,
  clean archive package build, and clean offline installation pass after final
  release documentation changes.
- [ ] Frontend tests, type check, production build, and packaged-static-asset
  synchronization pass after final documentation changes (the frontend is not
  changed, but the delivery boundary remains checked).

## Publication Evidence

- [ ] GitHub Actions CI is green for the final pre-tag commit.
- [ ] A manually dispatched pre-tag release-artifact run builds distributions,
  verifies checksums, and records provenance. Downloaded artifacts are checked
  independently against the enclosed manifest.
- [ ] README, methodology, ADR, schema, examples, release notes, dependency
  review, and this gate match the final intended diff.
- [ ] The final diff contains no secrets, generated capsules, policies,
  baselines, reports, caches, databases, or unrelated files.

## Tag And Publication Evidence

- [ ] The annotated `v0.8.0` tag passes CI and the tag-triggered release-artifact
  workflow publishes verified distributions, checksums, and provenance before a
  GitHub Release is considered complete.

Any non-applicable item requires a written rationale. Historical v0.7 evidence
does not satisfy this release gate.
