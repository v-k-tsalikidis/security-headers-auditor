# v0.5.0 Release Gate

## Release Classification

Current classification: **design and implementation in progress**.

The project must not be described as v0.5 complete until every applicable gate
below has recorded evidence.

## Methodology And Scope

- [x] Workspace product boundary and non-goals documented.
- [x] Framework evidence taxonomy and claims policy documented.
- [x] Loopback runtime decision recorded.
- [x] Persistence and migration decision recorded.
- [x] v0.4 CLI, scoring, assurance, and baseline behavior remains regression
  compatible through explicit tool-versus-methodology versioning (ADR 0004).

## Security And Privacy

- [x] Repo-specific threat model reviewed and implementation-aligned.
- [x] Loopback-only binding verified by integration test.
- [x] Session token is random, memory-only, and absent from logs and storage.
- [x] Host, Origin, content type, request size, and Fetch Metadata checks pass.
- [x] Cross-origin and tokenless requests fail.
- [x] Imported targets never auto-run; preview and explicit commit are tested.
- [x] Raw response values are absent from persisted summaries.
- [x] Query redaction and redirect authorization behavior remains effective.
- [x] Frontend CSP and no-third-party-runtime policy verified by static-serving
  integration test.

## Persistence And Migration

- [x] Workspace schema and validation implemented.
- [x] SQLite physical schema and restricted data path implemented.
- [x] Optimistic revision conflict tested.
- [x] Atomic save and rollback tested.
- [x] Future and malformed workspace imports rejected without data loss.
- [x] Database backup and migration rollback tested.
- [x] Canonical import/export round trip is deterministic.
- [x] Clear-data workflow is explicit and verified.

## Workspace Functionality

- [x] Create and open workspace.
- [x] Add, edit, disable, and remove authorized targets.
- [x] Configure explicit profile and assurance expectations.
- [x] Run current assessment through the Python engine.
- [x] Inspect findings, mappings, rationale, and limitations.
- [x] Run policy assurance and inspect regressions.
- [x] Create candidate baseline and explicitly approve reviewed change.
- [x] Export supported detailed report formats.
- [x] Recover from network, validation, persistence, and conflict errors.

## Framework Evidence

- [x] OWASP Secure Headers and ASVS sources re-reviewed.
- [x] WSTG-CONF-14 coverage and limitations represented.
- [x] NIST relationships remain control-informed only.
- [x] ATT&CK threat context is non-scoring and primary-source grounded.
- [x] D3FEND relationships are marked inferred where applicable.
- [x] Reports contain no compliance or certification claim.
- [x] SARIF 2.1.0 output validates against the official OASIS schema.

## Quality And Packaging

- [x] Python and frontend unit tests pass.
- [x] API contract and hostile-origin integration tests pass.
- [x] Browser end-to-end workflow passes without public remote targets.
- [x] Desktop and mobile responsive QA passes.
- [x] Keyboard, focus, semantics, contrast, zoom, and reduced-motion review
  passes within documented limits.
- [x] Built UI is packaged in wheel and works from an offline install.
- [x] Dependency and license review complete.
- [ ] GitHub Actions supported Python and Node matrix is green.
- [ ] README, tutorial, screenshots, and release notes match actual behavior.
- [ ] Repository diff contains no reports, secrets, databases, caches, or
  unrelated files.

The project may be described as v0.5 complete only when every applicable item is
checked and evidenced. Any non-applicable item requires written rationale.
