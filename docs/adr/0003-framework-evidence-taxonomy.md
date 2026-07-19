# ADR 0003: Framework Evidence Taxonomy

**Status:** Accepted
**Date:** 2026-07-19

## Context

Version 0.4 stores selected OWASP ASVS and NIST SP 800-53 relationships under a
single supporting-evidence policy. Adding OWASP WSTG, MITRE ATT&CK, or MITRE
D3FEND without distinguishing their purposes would invite misleading compliance
claims and could turn report identifiers into decoration.

## Decision

Keep framework relationships non-scoring and classify each mapping by evidence
family:

- `verification-requirement`;
- `test-procedure`;
- `security-control`;
- `threat-mitigation`;
- `defensive-technique`;
- `technical-format`.

Each mapping records:

- framework and version;
- stable requirement or technique identifier;
- evidence family;
- relationship type;
- confidence: `direct`, `strong`, `related`, or `inferred`;
- rationale;
- limitations;
- primary-source citation.

Reports group mappings by evidence family. They do not combine them into a
framework score, coverage percentage, badge, certification, or conformity
decision.

## Consequences

- ASVS and WSTG can explain verification and testing coverage.
- NIST can remain a broader control-informed relationship.
- ATT&CK can provide threat context without pretending to be a compliance
  framework.
- D3FEND can be shown only with explicit inferred confidence where no
  header-specific defensive technique exists.
- Mapping changes continue to invalidate approved baselines for review.

## Claim Boundary

Permitted:

> OWASP-informed header assessment with versioned ASVS evidence mappings,
> WSTG-aligned test coverage, NIST control relationships, and MITRE ATT&CK
> threat context.

Not permitted:

> OWASP, NIST, MITRE ATT&CK, D3FEND, GDPR, or PCI DSS compliant.

Specific machine-readable output conformance, such as SARIF 2.1.0, may be
claimed only when validated against the official schema in the release gate.
