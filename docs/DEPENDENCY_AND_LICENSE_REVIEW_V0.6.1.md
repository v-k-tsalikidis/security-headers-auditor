# v0.6.1 Dependency And License Revalidation

**Reviewed:** 2026-07-19

This is an engineering revalidation for v0.6.1, not legal advice. It compares
the release source with v0.6.0 and supplements the recorded
[v0.6 inventory](DEPENDENCY_AND_LICENSE_REVIEW_V0.6.md).

## Dependency Scope

- v0.6.1 adds no Python runtime, test, frontend production, frontend build, or
  packaged dependency. `pnpm-lock.yaml` is unchanged.
- `frontend/package.json` now declares the pre-existing `pnpm@11.9.0` tool
  version. This makes the CI package-manager selection explicit; it does not
  add a shipped dependency or alter the lockfile resolution.
- The shipped Python runtime remains standard-library-only plus packaged
  workspace assets. The reviewed frontend runtime closure and licenses remain
  `react`, `react-dom`, `scheduler` (MIT), and `lucide-react` (ISC).
- The v0.6 reviewed Python build/test toolchain remains unchanged:
  `pip==26.1.2`, `setuptools==83.0.0`, `build==1.5.0`, and
  `packaging==26.2`; the optional test dependency remains `jsonschema`.

## Delivery-Control Scope

GitHub Actions are not bundled into the wheel or source distribution, but they
do build, attest, and publish it. Their immutable SHA pins were deliberately
reviewed because GitHub reported Node 20 runtime deprecation notices in the
v0.6 workflow:

- `actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd` (`v5`) uses
  Node 24.
- `actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f` (`v6`)
  uses Node 24.
- `actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131`
  (`v7`) uses Node 24.
- `actions/cache@caa296126883cff596d87d8935842f9db880ef25` (`v5`) uses
  Node 24 and preserves the pnpm-store cache previously provided by
  `actions/setup-node`. The latter's automatic package-manager cache is
  explicitly disabled so only the reviewed cache key based on the frontend
  lockfile is used.
- `actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1` (`v6`)
  uses Node 24.
- The Node 20 `pnpm/action-setup` action is removed. The official Corepack
  bundled with Node 24 activates exactly `pnpm@11.9.0`; the workflow asserts
  that version before any install or build step.

The immutable pins for `actions/setup-node` and `actions/attest` remain
unchanged; both declare Node 24. The workflow stays on GitHub-hosted Ubuntu
runners; no self-hosted runner support claim is introduced.

## Distribution Controls

- `THIRD_PARTY_NOTICES.md` remains a declared wheel license file and is checked
  in the release workflow.
- The release workflow still builds from a clean GitHub checkout, rejects
  `.DS_Store` entries in the wheel, creates an artifact-relative `SHA256SUMS`
  manifest, and records artifact provenance before a tag-triggered GitHub
  Release can be published.
- v0.6.1 introduces no new third-party executable code, network service, or
  runtime capability in the auditor itself.

Any dependency, lockfile, license, or build-tool change after this review
requires a fresh record and release-impact assessment.
