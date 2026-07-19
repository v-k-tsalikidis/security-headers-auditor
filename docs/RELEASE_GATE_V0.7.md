# v0.7 Release Gate

## Release Classification

Current classification: **release candidate; not yet tagged or published**.

No `v0.7.0` tag, GitHub Release, announcement, or completeness claim is
permitted until each applicable item has reproducible evidence.

## Scope And Methodology

- [x] Scope is limited to Controlled Route Assurance: a separately versioned
  baseline for the existing explicit, same-origin route-comparison manifest.
- [x] Tool version is `0.7.0`; methodology remains `0.5.0`. Scoring, profiles,
  CSP parser behavior, target-policy assurance, and framework mappings are
  unchanged.
- [x] The route-baseline schema is self-contained and validates offline; it does
  not use remote schema retrieval.
- [x] Candidate writing refuses an existing path. Candidate creation and
  baseline enforcement cannot be combined in one CLI invocation.

## Security, Privacy, And Claims

- [x] Route assurance requests only the existing operator-supplied 2–25
  same-origin, query-free routes and preserves blocked cross-origin redirects.
- [x] Baselines and compact route outputs omit raw response-header values,
  credentials, cookies, query strings, fragments, runtime timestamps, and
  approval identity.
- [x] Scope, schema, methodology, mapping-set, route ID, path, and profile
  mismatch fail safely and require review/re-baselining.
- [x] A route baseline remains drift evidence, not a security pass, waiver,
  vulnerability decision, compliance decision, coverage proof, or browser
  runtime validation.
- [x] No dependency, hosted service, telemetry, authentication, crawling,
  fuzzing, exploitation, or framework claim is added.

## Functional And Regression Evidence

- [x] Deterministic unit tests cover matching baselines, score/control drift,
  operational failures, baseline tampering, candidate overwrite refusal,
  schema validation, compact output, and CLI mode ambiguity.
- [x] Existing route-comparison behavior still requests exactly the declared
  route set and keeps same-profile variance review-only.
- [ ] Final Python suite, compile check, deterministic route candidate/enforcement
  fixture, package build, and clean offline installation pass after the final
  release documentation changes.
- [ ] Frontend tests, type check, production build, and packaged-static-asset
  synchronization pass after the final release documentation changes.

## Publication Evidence

- [ ] GitHub Actions CI is green for the final pre-tag commit.
- [ ] A manually dispatched pre-tag release-artifact run builds distributions,
  verifies checksums, and records provenance. Downloaded artifacts are checked
  independently against the enclosed manifest.
- [ ] README, methodology, ADR, schemas, examples, release notes, dependency
  review, and this gate match the final intended diff.
- [ ] The final diff contains no secrets, candidates, baselines, reports,
  caches, databases, or unrelated files.

## Tag And Publication Evidence

- [ ] The annotated `v0.7.0` tag passes CI and the tag-triggered release-artifact
  workflow publishes verified distributions, checksums, and provenance before a
  GitHub Release is considered complete.

Any non-applicable item requires a written rationale. Historical v0.6.1
evidence does not satisfy this release gate.
