# v0.7 Dependency And License Revalidation

**Scope:** Controlled Route Assurance
**Status:** Completed for stable v0.7.0 (2026-07-19)

This record is an engineering review, not legal advice. v0.7 adds only
standard-library Python code and documentation:

- no Python runtime, optional-test, frontend production, frontend build, or
  lockfile dependency is added or upgraded;
- route-baseline serialization uses the existing Python `json` library;
- route-baseline comparison, SHA-free compact reporting, and schema validation
  reuse the existing package and test tooling;
- no new third-party network service, hosted processor, telemetry, or remote
  runtime asset is introduced.

The Apache-2.0 project license and existing third-party notices therefore remain
applicable without a dependency inventory change. The existing CI/release
workflow, immutable action pins, checksum manifest, and provenance attestation
continue to be the v0.7 delivery controls.

Any later dependency, license, lockfile, or build-tool change requires a new
review and must not be silently bundled into the v0.7 release.
