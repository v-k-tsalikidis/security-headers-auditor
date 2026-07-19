# v0.7 Release Gate

## Release Classification

Current classification: **stable; `v0.7.0` published 2026-07-19**.

The annotated `v0.7.0` tag, GitHub Release, release distributions, checksums,
and provenance evidence have each been independently verified. This record
captures the release evidence; it does not turn route-assurance results into a
security, compliance, or effectiveness claim.

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
- [x] Final Python suite (`140` tests), compile check, deterministic route
  candidate/enforcement fixture, clean archive package build, and clean offline
  installation passed for the tagged source.
- [x] Frontend tests (`6` tests), type check, production build, and
  packaged-static-asset synchronization passed for the tagged source.

## Publication Evidence

- [x] GitHub Actions [CI run 33](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29703007020)
  is green for final pre-tag commit `5338cbb5c53c2b3188f49f88dd2c949007d2f3d0`.
- [x] Manually dispatched [pre-tag release-artifact run 9](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29703101606)
  built distributions, verified checksums, and recorded provenance. Its downloaded
  artifact was independently checked against its enclosed manifest.
- [x] README, methodology, ADR, schemas, examples, release notes, dependency
  review, and this gate matched the final intended tag diff.
- [x] The final diff was checked for secrets, candidates, baselines, reports,
  caches, databases, and unrelated files before tagging.

## Tag And Publication Evidence

- [x] The annotated `v0.7.0` tag passes [CI run 34](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29703185450).
  The tag-triggered [Release Artifacts run 10](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29703185459)
  successfully built, checksumed, uploaded, provenance-attested, and published
  the release. The published [GitHub Release v0.7.0](https://github.com/v-k-tsalikidis/security-headers-auditor/releases/tag/v0.7.0)
  contains the wheel, source distribution, and `SHA256SUMS`.

## Verification Record

- Tag commit: `5338cbb5c53c2b3188f49f88dd2c949007d2f3d0`; annotated tag object:
  `a125df22e99cefae7def4ed4385f4d25001eea46`.
- Tag-workflow artifact: `security-headers-auditor-dist-5338cbb5c53c2b3188f49f88dd2c949007d2f3d0`
  (artifact `8447076688`), GitHub digest
  `sha256:aaf31d530c2f6d0f3dbebcf87edd1aad498524e0a67f577fb06d5175e4e55d39`.
  The downloaded archive matched that digest and its internal `SHA256SUMS`
  verified both distributions.
- The release downloads were independently rechecked against GitHub's recorded
  SHA-256 digests and the published `SHA256SUMS`; both the wheel and source
  distribution verified successfully.
- The tag release job completed the `Attest release distributions` step before
  publication. The hash manifest provides integrity checking; provenance is
  delivery evidence, not an assertion that a target is secure.

Any non-applicable item requires a written rationale. Historical v0.6.1
evidence does not satisfy this release gate.
