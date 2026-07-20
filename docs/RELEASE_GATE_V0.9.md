# v0.9 Release Gate

## Release Classification

Current classification: **release candidate; not published**.

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

- [ ] Final source diff, documentation, dependency review, package contents,
  secret scan, and CI are verified against the intended tag commit.
- [ ] Pre-tag release artifacts, checksums, and provenance are verified.
- [ ] Annotated `v0.9.0` tag, tag-triggered CI, published release artifacts,
  checksums, and provenance are independently verified.
