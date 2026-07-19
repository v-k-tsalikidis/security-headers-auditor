# v0.6.1 Release Gate

## Release Classification

Current classification: **stable; v0.6.1 published on 2026-07-19**.

This gate is evidence-driven. No `v0.6.1` tag, GitHub Release, announcement,
or claim of release completeness is permitted until every applicable item is
checked and recorded.

## Scope And Methodology

- [x] Scope is limited to supply-chain delivery controls, version identity, and
  release documentation. Auditor behavior, profiles, findings, schemas,
  mappings, baselines, and report semantics are unchanged from v0.6.0.
- [x] Tool version is `0.6.1`; methodology version remains `0.5.0`.
- [x] The Node 20 `pnpm/action-setup` action is removed. Corepack activates and
  asserts the already selected `pnpm@11.9.0`; the pnpm-store cache is retained
  through an immutable `actions/cache` v5 pin.
- [x] Checkout, setup-Python, artifact upload, artifact download, cache, Node
  setup, and attestation actions use reviewed immutable SHA pins whose action
  metadata declares Node 24.
- [x] The checksum manifest names the uploaded distribution files directly, so
  it remains verifiable after GitHub uploads the `dist/*` glob as a flattened
  artifact.

## Security, Privacy, And Claims

- [x] The auditor's read-only, operator-scoped, non-crawling boundaries are
  unchanged. No authentication, fuzzing, exploitation, brute force, or hosted
  result delivery is added.
- [x] The delivery patch does not introduce target or response-data storage,
  new network requests from the auditor, or a new third-party runtime
  dependency.
- [x] Framework mappings remain supporting engineering evidence only; no
  certification, compliance, endorsement, or security-effectiveness claim is
  added.
- [x] Dependency and license revalidation records the action-pin review and no
  shipped dependency change.

## Functional And Regression Evidence

- [x] Full Python suite, compile check, deterministic assurance fixture, and
  package build pass after the final source/documentation changes.
- [x] Frontend test, type check, production build, and packaged-asset
  synchronization pass after the final source/documentation changes.
- [x] Workflow YAML and every action pin are reviewed for the final diff; no
  action used by CI or release declares Node 20.
- [x] Built wheel and source distribution contain required assets and notices;
  a clean offline wheel installation passes.

## Local Verification Evidence

- On 2026-07-19, Python compilation and all 135 deterministic unit tests
  passed. The CI assurance fixture generated matching candidate baseline,
  JSON, SARIF, and JUnit outputs through the installed v0.6.1 CLI.
- Corepack activated exactly pnpm `11.9.0`; all 6 frontend tests, type check,
  production build, and packaged-static-asset synchronization passed.
- A clean Git archive with the final tracked v0.6.1 source applied built a
  wheel and source distribution using the pinned release toolchain. The wheel
  contained the workspace assets and license notice, contained no `.DS_Store`,
  and passed a clean `--no-index --no-deps` installation and CLI-help check.
- The exact checksum-generation command was then rerun in a fresh clean
  archive; the artifact-relative manifest verified both distributions directly.
- All workflow YAML files parse successfully. The final immutable action pins
  were checked against their official action metadata: checkout v5,
  setup-python v6, setup-node v5, cache v5, upload-artifact v6,
  download-artifact v7, and attest v4 each declare Node 24.

## Publication Evidence

- [x] GitHub Actions supported Python/Node CI is green for the final pre-tag
  commit without a Node 20 runtime deprecation notice.
- [x] A manually dispatched pre-tag release-artifact run builds distributions,
  runs the full suite, creates `SHA256SUMS`, and records provenance. The
  downloaded artifact and checksum manifest are independently verified.
- [x] README, release notes, dependency review, and gate match the final
  behavior and intended repository diff.
- [x] Repository diff contains no secrets, databases, reports, caches, or
  unrelated files.

## Tag And Publication Evidence

## Pre-Tag Evidence

- GitHub [CI #29](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29700484971)
  passed for final pre-tag commit `9b9fb01`, with all Python matrix and frontend
  jobs successful. The final job logs contain no GitHub Node 20 action-runtime
  deprecation notice.
- Manually dispatched [Release Artifacts #7](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29700551673)
  passed for `9b9fb01`; its publish job was skipped by design because no tag
  existed. The downloaded artifact matched GitHub's published artifact digest
  `049f59ffe360e41913b53d05975668235ea283c8735807c366a289f570192922`, and
  its wheel and source archive matched the enclosed, artifact-relative
  `SHA256SUMS` manifest directly.
  [Attestation #36059553](https://github.com/v-k-tsalikidis/security-headers-auditor/attestations/36059553)
  records Sigstore build provenance for the wheel, source archive, and checksum
  manifest.

## Tag And Publication Evidence

- Annotated tag `v0.6.1` points to `9b9fb01`. GitHub
  [CI #30](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29700613781)
  passed for that tag.
- Tag-triggered [Release Artifacts #8](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29700613787)
  passed: package and publish jobs both succeeded, and the workflow created the
  public [v0.6.1 GitHub Release](https://github.com/v-k-tsalikidis/security-headers-auditor/releases/tag/v0.6.1).
- The downloaded tag artifact matched GitHub's published artifact digest
  `ed78a67a3710f1364784ebb10ef6d77dc77e2b505731302def2a60171ed3c0d8`, and
  its wheel and source archive matched the enclosed `SHA256SUMS` manifest
  directly. [Attestation #36059726](https://github.com/v-k-tsalikidis/security-headers-auditor/attestations/36059726)
  records tag-scoped Sigstore build provenance for the wheel, source archive,
  and checksum manifest.

Any non-applicable item requires a written rationale. Historical v0.6 evidence
does not satisfy this v0.6.1 release gate.
