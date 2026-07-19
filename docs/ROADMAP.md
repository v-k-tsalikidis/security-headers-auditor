# Post-v0.6.1 Product Roadmap

**Status:** Active planning document
**Reviewed:** 2026-07-19
**Current stable release:** v0.6.1

## Direction

Security Headers Auditor is not becoming another universal header scanner. Its
next work must make a bounded, profile-aware assessment more useful in real
change control: first by detecting drift across an explicitly authorized route
set over time, then by making the resulting review evidence easier to move and
verify without exposing unnecessary response data.

The roadmap stays subordinate to the project's read-only, operator-authorized,
local-first, data-minimizing model. A capability is not a release commitment
until its design, threat impact, acceptance tests, and release gate are
complete.

## Foundation Completed

| Release | Completed outcome |
| --- | --- |
| v0.4 | Profile-aware scoring, versioned supporting evidence, policy-as-code, approved baselines, regression detection, and CI-native reports. |
| v0.5 | Local loopback workspace with protected state changes, explicit baseline approval, local persistence, and no hosted target collection. |
| v0.6 | Deterministic profile-definition export, explicit same-origin route comparison, and bounded CSP parser improvements. |
| v0.6.1 | Reproducible release artifacts, SHA-256 manifests, immutable CI action pins, and GitHub artifact provenance attestations. |

The former roadmap is therefore closed:

- [x] Machine-readable profile-definition export.
- [x] Controlled multi-response assessment for route-level profile comparison.
- [x] CSP parsing depth without a browser-policy-validation claim.
- [x] Signed/provenance-attested release artifacts after a completed release gate.

## v0.7 — Controlled Route Assurance

**Priority:** Next release candidate.

### Real problem

The current route comparison shows differences among 2–25 known routes in one
authorized run. It cannot tell a reviewer whether a previously reviewed route
set has drifted between releases. Teams are then forced to compare reports by
hand, often with raw-header evidence that is broader and more sensitive than
the review needs.

### Outcome

Add an approved, data-minimized route baseline that detects meaningful
route-level configuration drift over time without turning the route manifest
into a crawler or a second continuous-assurance policy language.

### Planned scope

1. Define a dedicated, versioned route-baseline schema. It will be separate
   from the existing target-policy baseline and record only the explicit route
   scope, declared profile, score, and scored-control state needed for
   comparison.
2. Bind a baseline to one canonical route manifest: name, exact origin, route
   IDs, paths, and declared profiles. A manifest, methodology, or mapping-set
   mismatch must require review and re-baselining; it must never be silently
   reinterpreted.
3. Produce a reviewable candidate only when every configured route has an
   assessable response. Candidate creation and approval remain distinct
   operations. Baseline approval will never convert a weak configuration into
   a passing security verdict.
4. Report only defined drift signals: scope mismatch, score decrease, worse
   control status or severity, and lost scored points. Keep current in-run
   control variances as review signals, not failures by themselves.
5. Emit compact JSON and Markdown suitable for CI review. Preserve the
   existing no-raw-header rule for route artifacts, redact query strings and
   fragments, and keep the current stable exit-code boundary: invalid or
   incompatible configuration is operational failure; detected regressions are
   policy review failure.

### Explicit non-goals

- no path discovery, crawling, wildcard routes, or route enumeration;
- no authentication, cookies, credential storage, browser automation, fuzzing,
  payload injection, exploitation, or bypass;
- no cross-origin route set, query-bearing route, redirect opt-in, background
  scheduling, notification service, or hosted result store;
- no compliance result, framework coverage percentage, vulnerability claim, or
  proof of browser runtime behaviour;
- no automatic overwrite, approval, or migration of a route baseline.

### Methodology and framework boundary

v0.7 is intended to compare the existing evaluated control state, not to change
the score, profile rules, CSP semantics, or framework mappings. Therefore the
current methodology version can remain valid only if implementation confirms
that those semantics are unchanged. Any scoring or mapping change must follow
the existing versioning rule and force a reviewed migration.

No framework identifier will be added merely to decorate route output. Existing
OWASP, NIST, MITRE, and technical-format relationships remain versioned,
supporting evidence with their current limitations.

### Acceptance gate

v0.7 cannot be released until deterministic tests prove all of the following:

- schema and manifest validation complete before any request;
- exactly the declared, same-origin, 2–25 query-free routes are requested;
- candidates and comparisons contain no raw header values, credentials, query
  strings, fragments, or runtime-only secrets;
- scope, methodology, mapping, profile, score, status, severity, and
  points-regression cases behave deterministically;
- malformed, future, mixed-origin, partial-run, and baseline-tampering inputs
  fail safely without overwriting an approved artifact;
- a regression is distinguishable from an operational error in JSON, Markdown,
  exit codes, and CI outputs;
- the existing audit, assurance, workspace, report-escaping, privacy, and
  redirect-boundary tests remain green.

Before code starts, this release requires a methodology specification, an ADR,
a data-classification review, and fixtures covering intentional route variance
as well as actual drift.

## v0.8 — Portable Review Evidence Capsule

**Priority:** Conditional; start only after v0.7 has passed its release gate
and a real review workflow shows that its outputs reduce manual comparison.

### Real problem

An assurance decision is currently distributed across policy files, approved
baselines, route manifests, reports, and CI artifacts. Reviewers need to know
which versioned configuration produced an outcome without collecting a broad
archive of raw response evidence or trusting screenshots.

### Intended outcome

Create one canonical, portable review capsule that binds the exact policy or
route-manifest scope, applicable baseline, methodology and mapping versions,
profile-definition fingerprint, and compact assessment result through an
offline-verifiable SHA-256 manifest.

### Guardrails

- The first capsule format excludes raw response-header values by default and
  includes no credentials, cookies, query strings, fragments, or workspace
  session data.
- It is a review artifact, not a security attestation, a signed identity
  statement, or proof that a target is secure. A hash manifest detects changes
  only when the reviewer has a trusted expected digest; it does not authenticate
  an author.
- Generation and verification perform no target request and no third-party
  network call. Organizational signing, retention, access control, and CI
  artifact storage remain outside the tool.
- The design must state which target-scope information is retained, why it is
  necessary for review, and how operators should protect it as security
  evidence.

### Entry criteria

- v0.7 is stable and its compact artifacts have been exercised in a controlled
  CI or review workflow;
- a threat model and schema design demonstrate bounded input size, canonical
  serialization, path-traversal resistance, safe extraction/verification, and
  privacy-preserving defaults;
- the product retains a clear advantage over a generic report archive rather
  than merely packaging existing files.

## Work Deliberately Not Scheduled

These ideas are outside the current product direction unless a new, concrete,
authorized user problem justifies them and their safety case is accepted:

- hosted scanning, accounts, teams, RBAC, telemetry, cloud synchronization, or
  a multi-tenant platform;
- authenticated scanning, secret handling, crawling, discovery, fuzzing,
  exploitation, or vulnerability confirmation;
- browser-equivalent CSP enforcement, DOM/meta-policy inspection, nonce
  lifecycle verification, resource-graph crawling, or claims of bypass
  resistance;
- compliance badges, framework scores, certification language, or automated
  risk acceptance;
- broad SIEM, ticketing, alerting, notification, or continuous-monitoring
  integrations.

## Delivery Discipline For Every Roadmap Item

1. Write the problem statement, authorized-use boundary, non-goals, threat
   impact, data classification, framework-evidence impact, and acceptance
   criteria before implementation.
2. Use a versioned schema and deterministic fixtures. Reject unknown future
   versions and incompatible baselines rather than guessing their meaning.
3. Keep evidence, engineering assessment, policy result, and compliance claim
   separate in both data and presentation.
4. Verify the full Python suite, frontend tests/type check/build when affected,
   package contents, CI, and relevant browser/accessibility QA.
5. Do not create a public tag, GitHub Release, or announcement until the
   release gate records complete, reproducible evidence.
