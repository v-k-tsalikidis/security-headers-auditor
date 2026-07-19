# v0.6 Dependency And License Revalidation

**Reviewed:** 2026-07-19

This is an engineering revalidation for v0.6.0, not legal advice. It compares
the release source with `v0.5.0` and supplements the recorded
[v0.5 inventory](DEPENDENCY_AND_LICENSE_REVIEW_V0.5.md).

## Dependency Scope

- v0.6.0 adds no Python runtime dependency, optional test dependency, frontend
  production dependency, frontend build dependency, or lockfile change.
- The shipped Python runtime therefore remains standard-library-only plus the
  packaged workspace assets. The bundled frontend runtime closure and licenses
  remain the reviewed `react`, `react-dom`, `scheduler` (MIT), and
  `lucide-react` (ISC).
- The v0.5 reviewed build/test toolchain and its pinned release versions remain
  unchanged: `pip==26.1.2`, `setuptools==83.0.0`, `build==1.5.0`, and
  `packaging==26.2`; the optional test dependency remains `jsonschema`.

## Distribution Controls

- `THIRD_PARTY_NOTICES.md` is declared as a wheel license file, and the release
  workflow checks that it is present in the built wheel.
- The release workflow builds from a clean GitHub checkout, rejects `.DS_Store`
  entries in the wheel, creates `SHA256SUMS`, and records artifact provenance
  before a tag-triggered GitHub Release can be published.
- The v0.6 source changes are parser, CLI, schema, documentation, and test
  changes; they introduce no new third-party executable code or network service.

Any dependency, lockfile, license, or build-tool change after this revalidation
requires a fresh review with its release impact recorded.
