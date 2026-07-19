# v0.8 Dependency And License Revalidation

**Scope:** Portable review evidence capsule
**Status:** Release-candidate review

This is an engineering review, not legal advice. v0.8 uses only Python standard
library modules already available to the supported runtime: `hashlib`, `json`,
`pathlib`, `stat`, `urllib.parse`, and `zipfile` (plus `io` and dataclasses).
It adds no runtime, test, frontend, build, package, lockfile, hosted-service, or
telemetry dependency.

The Apache-2.0 project license and existing third-party notices remain
applicable. The existing immutable-action CI, package checks, SHA-256 manifests,
and provenance attestation remain delivery controls. The v0.8 release gate must
confirm that no accidental dependency or license change is bundled with this
feature.
