# ADR 0007: Controlled Route Assurance

**Status:** Accepted for v0.7 implementation
**Date:** 2026-07-19

## Context

ADR 0005 intentionally limits route comparison to a single, explicit run. It
shows profile-consistent route variance but cannot detect time-based drift. A
generic multi-target policy cannot fill that gap without conflating route scope
comparison with target requirements and encouraging larger, less controlled
inventories.

## Decision

Add a distinct route-assurance baseline artifact, versioned independently from
the existing policy baseline. It is bound to one canonical route manifest and
stores only the route identity, declared profile, score, and scored-control
state necessary for comparison.

The CLI writes only new candidate files. An operator reviews and approves the
candidate outside the tool before passing it back as a baseline. The tool
rejects incompatible schema, methodology, mapping, or manifest changes. It
does not automatically migrate, overwrite, or approve a route baseline.

Regression output covers only worsened score/control state and preserves route
variance as a non-failing review signal. Raw response-header values remain
outside both baseline and compact output.

## Consequences

- Teams gain bounded route-level drift detection without a crawler, scanner,
  monitoring service, or second policy language.
- Scope changes require an explicit review and re-baseline rather than a silent
  interpretation of a changed route inventory.
- v0.7 does not alter scoring or framework mappings, so methodology `0.5.0`
  remains valid.
- The artifact is security evidence and must be protected by the operator; it
  is not a compliance or security-effectiveness attestation.
