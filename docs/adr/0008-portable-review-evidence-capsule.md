# ADR 0008: Use A Deterministic Offline Review Evidence Capsule

**Status:** Accepted for v0.8 implementation; release evidence pending

## Context

Policy and route-assurance review can involve separately stored scope files,
compact output, baselines, profile definitions, and CI artifacts. A reviewer
needs to establish what was evaluated without collecting raw response evidence
or trusting a screenshot. A generic ZIP archive would be easy to create but
does not reliably express scope, privacy boundaries, or safe verification.

## Decision

Introduce one local-only `security-headers-auditor.evidence-capsule` format.
It is a deterministic uncompressed ZIP with an allowlisted entry set, canonical
UTF-8 JSON, fixed timestamps and permissions, SHA-256 manifest, strict
scope/assessment/baseline compatibility checks, and a verifier that reads in
place without extraction.

The capsule accepts only dedicated compact `review-json` assessments. It keeps
scope separate from outcome data, includes no raw response-header values, and
rejects query-bearing or credential-bearing policy scope. The verifier binds the
current static profile-definition export so that a reviewer can see the applied
methodology and mapping context.

## Consequences

- Reviewers gain one reproducible evidence package whose contents can be
  validated offline.
- Operators retain responsibility for trusted expected digests, access control,
  retention, and approval. The format supplies integrity evidence, not identity
  or authorization.
- Future formats are rejected instead of being silently interpreted. This makes
  migration explicit but requires new release documentation when contracts
  change.
- The feature remains a small standard-library implementation with bounded
  parsing and no new runtime dependency.
