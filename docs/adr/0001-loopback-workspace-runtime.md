# ADR 0001: Loopback Workspace Runtime

**Status:** Accepted for implementation
**Date:** 2026-07-19

## Context

The existing Python CLI can request arbitrary authorized HTTP(S) targets. A
browser-only application cannot reliably inspect arbitrary response headers
because browser cross-origin rules intentionally hide them. A hosted scanning
service would introduce accounts, remote target disclosure, multi-tenancy,
operational cost, and a substantially different privacy and threat model.

The workspace UI must remain another interface to the same audit engine. It
must not create a second scoring implementation or broaden the product into a
general security platform.

## Decision

Add a local workspace command that starts a loopback-only HTTP service and
serves a bundled React/TypeScript interface.

```text
security-headers-auditor workspace
```

Runtime properties:

- bind to `127.0.0.1`, never `0.0.0.0`, by default;
- use one same-origin UI and JSON API;
- call the existing `audit_headers` and `run_assurance` domain functions;
- perform no cloud synchronization, analytics, telemetry, or remote asset
  loading;
- require a random, memory-only session token for every state-changing or audit
  API call;
- validate `Host`, `Origin`, content type, request size, and Fetch Metadata
  headers where available;
- send a restrictive Content Security Policy and anti-framing headers;
- never auto-run imported targets;
- keep the CLI fully functional without frontend tooling at runtime.

The token is delivered in the URL fragment, removed from browser history after
bootstrap, retained only in page memory, and never written to logs or
persistence.

## Consequences

Positive:

- the user can run real audits from the interface without disclosing targets to
  a third-party service;
- browser and CLI results share one evaluator;
- the packaged application remains usable offline except for the authorized
  target requests;
- the UI can be tested independently with a fake API.

Costs:

- a local HTTP API creates localhost request-forgery and DNS-rebinding risks;
- the Python package must ship built frontend assets;
- API schemas and UI assets require versioned compatibility tests;
- only one trusted local user is supported.

## Rejected Alternatives

- Hosted scanner: rejected because it changes the privacy and operating model.
- Browser-only scanner: rejected because CORS prevents reliable header access.
- Electron or Tauri desktop shell: rejected for baseline size and additional
  supply-chain surface.
- Separate frontend scoring engine: rejected because it can drift from the CLI.

## Non-Goals

- remote access to the workspace service;
- organization accounts, teams, RBAC, or multi-tenancy;
- scheduling, notifications, ticketing, or SIEM ingestion;
- crawling, authenticated scanning, fuzzing, or browser automation;
- replacing the existing CLI and CI workflow.
