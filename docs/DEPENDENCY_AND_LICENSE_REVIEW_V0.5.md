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
  installing `pip==26.1.2`, `setuptools==83.0.0`, `build==1.5.0`,
  `packaging==26.2`, and the exact reviewed `jsonschema==4.26.0` closure.

## Release Controls

- CI and release workflows pin Actions by immutable commit ID, with the major
  version recorded in comments for reviewability.
- The release workflow is configured to pin the audited Python build toolchain,
  build without isolation, verify the wheel's UI and notice files, create
  SHA-256 checksums, and produce a GitHub Sigstore/SLSA provenance attestation
  before publication. Manual [Release Artifacts #2](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29697158619)
  passed on 2026-07-19 after an initial runner-only missing-`packaging`
  dependency was pinned; its [attestation #36053776](https://github.com/v-k-tsalikidis/security-headers-auditor/attestations/36053776)
  covers the wheel, source archive, and checksum manifest.
- A future dependency, license, lockfile, or build-tool update requires this
  review to be rerun and its release impact recorded.
