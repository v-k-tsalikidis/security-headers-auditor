# v0.8 Release Gate

## Release Classification

Current classification: **stable; `v0.8.0` published 2026-07-20**.

The annotated `v0.8.0` tag, GitHub Release, release distributions, checksums,
and provenance evidence have each been independently verified. This record
captures delivery and integrity evidence; it does not make a security,
compliance, or effectiveness claim about an assessed target.

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
- [x] Final Python suite (`146` tests), compile check, deterministic
  command-line fixtures, clean archive package build, and clean offline
  installation passed for the tagged source.
- [x] Frontend tests (`6` tests), type check, production build, and
  packaged-static-asset synchronization passed for the tagged source.

## Publication Evidence

- [x] GitHub Actions [CI run 35](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29704436684)
  is green for final pre-tag commit `0bc9f6234ff60230485e542a255f91e7434d4a84`.
- [x] Manually dispatched [pre-tag release-artifact run 11](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29704546117)
  built distributions, verified checksums, and recorded provenance. Its downloaded
  artifact was independently checked against its enclosed `SHA256SUMS`.
- [x] README, methodology, ADR, schema, examples, release notes, dependency
  review, and this gate matched the final intended tag diff.
- [x] The final diff was checked for secrets, generated capsules, policies,
  baselines, reports, caches, databases, and unrelated files before tagging.

## Tag And Publication Evidence

- [x] The annotated `v0.8.0` tag passes [CI run 36](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29704647202).
  The tag-triggered [Release Artifacts run 12](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29704647247)
  successfully built, checksumed, uploaded, provenance-attested, and published
  the release. The published [GitHub Release v0.8.0](https://github.com/v-k-tsalikidis/security-headers-auditor/releases/tag/v0.8.0)
  contains the wheel, source distribution, and `SHA256SUMS`.

## Verification Record

- Tag commit: `0bc9f6234ff60230485e542a255f91e7434d4a84`; annotated tag object:
  `0902a7408023c1c59ed64e750bf45c9e45f7b0d5`.
- Pre-tag artifact: `security-headers-auditor-dist-0bc9f6234ff60230485e542a255f91e7434d4a84`
  (artifact `8447480951`), GitHub digest
  `sha256:a5f9def0d0d60c821e1dc1ed5f2712a2fa66dd3cad7c8943ac793ff301fb0804`.
  Its downloaded archive and enclosed `SHA256SUMS` verified both distributions.
- Tag-workflow artifact: `security-headers-auditor-dist-0bc9f6234ff60230485e542a255f91e7434d4a84`
  (artifact `8447509968`), GitHub digest
  `sha256:032fd3cecd13df8f4ac15f67672d1c839eebb72f77a1137d462a2f2dd26a757c`.
  The downloaded archive matched that digest and its internal `SHA256SUMS`
  verified both distributions.
- The public release downloads were independently rechecked against GitHub's
  recorded SHA-256 digests and the published `SHA256SUMS`; both the wheel and
  source distribution verified successfully.
- The tag release job completed the `Attest release distributions` step before
  publication. The hash manifest provides integrity checking; provenance is
  delivery evidence, not an assertion that a target is secure.

Any non-applicable item requires a written rationale. Historical v0.7 evidence
does not satisfy this release gate.
