# v0.5 Dependency And License Review

**Reviewed:** 2026-07-19

This review covers the shipped Python wheel, the bundled workspace runtime, and
the toolchain that produces it. It is an engineering inventory, not legal
advice.

## Shipped Runtime

- The Python runtime has no third-party runtime dependency; its dependency
  surface is the standard library plus the packaged frontend assets.
- The frontend runtime closure contains `react`, `react-dom`, `scheduler`
  (MIT), and `lucide-react` (ISC). Their notices are included in
  `THIRD_PARTY_NOTICES.md` and are declared as wheel license files.
- `pnpm --dir frontend audit --prod --json` reported zero known advisories for
  the four production dependencies on the review date.

## Build And Test Toolchain

- The committed pnpm lockfile resolved 167 total frontend packages for the
  build/test environment. `pnpm --dir frontend audit --json` reported zero
  known advisories on the review date.
- The reviewed frontend license inventory contains Apache-2.0, BlueOak-1.0.0,
  BSD-2-Clause, BSD-3-Clause, CC0-1.0, ISC, MIT, MIT-0, and MPL-2.0. MPL-2.0
  applies to the build-only `lightningcss` packages and is not bundled into the
  wheel.
- The optional Python test dependency is `jsonschema` and its resolved closure
  (`attrs`, `jsonschema-specifications`, `referencing`, `rpds-py`) declares
  MIT licenses. It is not a shipped runtime dependency.
- A temporary isolated `pip-audit` review found no known vulnerabilities after
  installing `pip==26.1.2`, `setuptools==83.0.0`, `build==1.5.0`, and the
  exact reviewed `jsonschema==4.26.0` closure.

## Release Controls

- CI and release workflows pin Actions by immutable commit ID, with the major
  version recorded in comments for reviewability.
- The release workflow pins the audited Python build toolchain, builds without
  isolation, verifies the wheel's UI and notice files, creates SHA-256 checksums,
  and produces a GitHub Sigstore/SLSA provenance attestation before publication.
- A future dependency, license, lockfile, or build-tool update requires this
  review to be rerun and its release impact recorded.
