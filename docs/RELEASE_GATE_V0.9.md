# v0.9 Release Gate

## Release Classification

Current classification: **published and independently verified**.

## Scope And Methodology

- [x] Scope is limited to bounded local workspace session history and unique,
  timestamped explicit report exports.
- [x] Methodology (`0.5.0`), scoring, profiles, policy/baseline semantics,
  framework mappings, and target request behavior are unchanged.
- [x] Workspace schema `1.2` has deterministic migrations from `1.0` and `1.1`.

## Data And Safety Boundaries

- [x] History is capped at 50 compact entries and rejects malformed, duplicate,
  unknown, or raw-value fields.
- [x] Detailed results remain current-process memory and explicit exports; no
  hidden full-report archive or remote storage is added.
- [x] No dependency, hosted service, telemetry, authentication, crawling,
  fuzzing, exploitation, or automatic approval is added.

## Functional And Regression Evidence

- [x] Workspace migration, raw-value rejection, consecutive-session, dated
  filename, stale-summary, API, and frontend History-view regression coverage
  is present.
- [x] Final full Python suite (`152` tests), compile check, command-line
  fixtures, clean wheel/sdist build, package-content inspection, and isolated
  wheel installation passed locally.
- [x] Final frontend tests (`7` tests), type check, production build, and
  packaged-static-asset synchronization passed. A loopback browser smoke test
  loaded the packaged History view and rendered a persisted audit session with
  its timestamp, scope, target, score, outcome, and audit ID.

## Publication Evidence

- [x] Final source diff, documentation, dependency review, package contents,
  secret scan, and CI are verified against the intended tag commit.
- [x] Pre-tag release artifacts, checksums, and provenance are verified.
- [x] Annotated `v0.9.0` tag, tag-triggered CI, published release artifacts,
  checksums, and provenance are independently verified.

## Verification Record

- Intended tag source: annotated `v0.9.0` on commit
  [`77e997d`](https://github.com/v-k-tsalikidis/security-headers-auditor/commit/77e997dc3eacf335fc3e2ce1ac27b42f85074ecf).
  This includes the v0.9 workspace-history implementation, the current
  responsible-use boundary, product positioning, and packaged workspace UI.
- Local final verification passed: 152 deterministic Python tests, 7 frontend
  tests, type check, production asset build, clean wheel/sdist build,
  package-content inspection, and isolated offline wheel installation/CLI
  smoke test. The source/documentation diff and secret-pattern review were
  clean.
- [CI run 42](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29720814980)
  passed for the exact tag source.
- The manual pre-tag
  [Release Artifacts run 13](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29721042199)
  passed for the same commit. Its downloaded artifact matched its enclosed
  SHA-256 manifest, and GitHub recorded provenance attestations for both the
  wheel and source distribution.
- The tag-triggered
  [Release Artifacts run 14](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29721231253)
  passed and published the public
  [v0.9.0 release](https://github.com/v-k-tsalikidis/security-headers-auditor/releases/tag/v0.9.0).
  The published wheel and source archive were downloaded independently and
  both verified against the published `SHA256SUMS`. GitHub's release metadata
  records the same SHA-256 digests, and GitHub recorded one provenance
  attestation for each distribution.
