# ADR 0002: Workspace Persistence And Migrations

**Status:** Accepted for implementation
**Date:** 2026-07-19

## Context

The workspace needs durable target policies, an optional approved baseline, and
minimal run summaries. Browser IndexedDB would bind data to an origin and port,
making recovery and command-line interoperability awkward. A remote database is
outside the privacy model.

The existing policy and baseline formats are already versioned and validated.
The persistence design should reuse them instead of inventing parallel target
and finding models.

## Decision

Use Python's standard-library SQLite driver for local persistence. Store each
workspace as one canonical, versioned JSON document in an atomic row.

Database:

- OS-appropriate per-user application-data directory;
- file permissions restricted to the current user where supported;
- one `workspaces` table keyed by workspace UUID;
- integer `revision` for optimistic concurrency;
- `schema_version`, `updated_at`, and canonical JSON document;
- SQLite `PRAGMA user_version` for physical schema migrations;
- foreign keys enabled and a bounded busy timeout;
- no raw response header values in persisted run summaries.

Workspace document:

- workspace identity and display name;
- one existing versioned assurance policy;
- zero or one existing approved baseline;
- latest per-target summary containing score, profile, status, and control-state
  metadata only;
- created and updated timestamps;
- no authorization token, raw headers, cookies, credentials, or report body.

## Independent Versions

Three versions remain independent:

| Version | Purpose |
| --- | --- |
| Tool methodology version | Scoring and assurance semantics |
| Workspace document schema | Portable import/export contract |
| SQLite `user_version` | Physical table and index layout |

A methodology change can invalidate a baseline without changing the database
layout. A workspace JSON migration runs in memory and validates before write.

## Save And Conflict Rules

- The API reads a workspace with its current revision.
- A save must include that revision.
- A matching revision is committed in one transaction and incremented.
- A mismatch returns a conflict and does not overwrite newer data.
- The UI offers reload or export of the unsaved draft; it never silently uses
  last-write-wins.

## Migration Rules

1. Back up the database before a physical migration.
2. Run physical migrations in a single immediate transaction.
3. Update `PRAGMA user_version` only after all statements succeed.
4. Validate every workspace document before and after an in-memory content
   migration.
5. Never delete unknown fields or guess the meaning of a future version.
6. Reject future versions and missing migration links without changing data.
7. Keep deterministic fixtures for every supported migration path.
8. Make clear-data a separate confirmed action, never a migration side effect.

## Import And Export

- Maximum workspace import size: 2 MiB.
- Parse strict JSON only.
- Validate root keys, policy, baseline, identifiers, URLs, limits, and
  cross-record consistency.
- Show a preview and require confirmation before replacing local state.
- Do not run imported targets automatically.
- Export the canonical workspace document without SQLite metadata.

## Retention

The default retains one latest summary per target and the approved baseline.
Detailed reports remain explicit user exports. This avoids creating an
unbounded security-posture history or storing potentially sensitive raw header
values.

## Rejected Alternatives

- IndexedDB: rejected because persistence would vary by browser origin and
  selected port.
- Plain JSON file: rejected because conflict handling, atomic updates, and
  future indexes require more custom failure handling.
- SQL-normalized findings: rejected because it duplicates versioned domain
  contracts and increases migration surface.
- Raw response history: rejected by data minimization.
