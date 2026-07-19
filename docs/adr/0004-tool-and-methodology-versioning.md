# ADR 0004: Tool And Methodology Versioning

**Status:** Accepted and implemented
**Date:** 2026-07-19

## Context

Version 0.5 adds a local workspace, packaging, and framework-evidence
presentation. Its underlying header scoring, assurance policy, and approved
baseline semantics remain the v0.4 methodology. Using one version value for
both the distributable tool and the methodology would invalidate valid v0.4
policies and baselines merely because the interface changed.

## Decision

Keep two explicit versions:

| Value | v0.5 value | Purpose |
| --- | --- | --- |
| Tool version | `0.5.0` | Package metadata, CLI User-Agent, workspace UI, and release identity |
| Methodology version | `0.4.0` | Scoring, assurance-policy, baseline, and report compatibility contract |

Policy and baseline validation compares `methodology_version` only with the
methodology version. The workspace bootstrap exposes the tool version for UI
display. A future scoring or assurance semantic change must increment the
methodology version, explicitly invalidate prior baselines, and document the
migration or re-baselining decision.

## Consequences

- Existing v0.4 policies and approved baselines remain valid when used with the
  v0.5 workspace, subject to the independent evidence-mapping compatibility
  check.
- The package can accurately identify itself as v0.5 without claiming a new
  scoring methodology.
- Reports continue to identify the methodology that produced an assessment,
  rather than the UI or packaging version.
