# v0.9 Dependency And License Revalidation

**Scope:** Bounded local workspace audit history and timestamped exports
**Status:** Release-candidate review

v0.9 uses Python standard-library facilities already present in the supported
runtime (`dataclasses`, `datetime`, and `uuid`) plus the existing bundled React
workspace UI. It adds no Python runtime, test, frontend production, frontend
build, package, lockfile, hosted-service, telemetry, or third-party scanning
dependency.

The Apache-2.0 project license, existing third-party notices, immutable-action
CI, package checks, SHA-256 manifests, and provenance-attestation workflow
remain applicable. A dependency, lockfile, license, or build-tool change before
the final tag requires this record to be renewed.
