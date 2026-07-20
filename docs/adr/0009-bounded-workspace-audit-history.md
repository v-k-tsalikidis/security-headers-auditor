# ADR 0009: Retain Bounded Workspace Audit Sessions

**Status:** Accepted for v0.9.0 release candidate.

## Context

The workspace retained detailed evidence only for its latest in-memory run and
persisted only one latest summary per target. A later audit replaced that state.
Its export filename was derived only from the policy name, so exports from
different sessions could collide in the operator's downloads directory.

The product needs a reviewable local session trail without turning the workspace
into a broad archive of raw HTTP response evidence.

## Decision

Workspace schema `1.2` adds `audit_history`, a newest-first list capped at 50
entries. Each entry has a canonical UUID audit ID, UTC completion time, audit
scope, policy name, outcome, exit code, and compact score-level assessment
summaries. Unknown fields, malformed values, duplicate IDs, and more than 50
entries are rejected.

The active process retains the full detailed result only for the current run.
Every explicit report export receives a filename containing the policy scope,
UTC completion timestamp, and shortened unique audit ID. Full report content
is still retained only when the operator explicitly downloads it.

## Consequences

- Users can distinguish and revisit the last 50 local audit sessions in the
  workspace after subsequent runs and restarts.
- Successive report downloads have collision-resistant, date-bearing filenames.
- Existing `1.0` and `1.1` workspace documents migrate deterministically with
  empty history; no prior raw response evidence is invented or recovered.
- Scoring, profiles, methodology, baselines, network behavior, and framework
  evidence mappings remain unchanged.
- Session summaries still contain audit context and must be handled as local
  security-review data.
