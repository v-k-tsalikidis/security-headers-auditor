# Continuous Assurance Guide

## Purpose

Continuous assurance compares authorized HTTP response configuration with an
explicit policy and, optionally, an approved baseline. It is intended for CI/CD
or scheduled execution where silent configuration drift must become visible.

It is not a monitoring service. Scheduling, credentials, notifications, artifact
retention, and escalation remain responsibilities of the deployment environment.

## 1. Create The Policy

Start from [`../examples/audit-policy.json`](../examples/audit-policy.json) and
validate it against
[`schemas/audit-policy.schema.json`](schemas/audit-policy.schema.json).

Use:

- stable, non-secret target identifiers;
- explicit `app`, `api`, or `brochure` profiles;
- the narrowest authorized URL;
- thresholds agreed by the system owner;
- `required` only for capabilities the application is designed to support;
- `not_applicable` only as a documented decision.

Do not place bearer tokens, reset links, session identifiers, or personal data in
policy URLs. Policy files belong under the same access controls as deployment
configuration.

## 2. Run Without A Baseline

```bash
security-headers-auditor \
  --policy audit-policy.json \
  --format html \
  --output reports/assurance-review.html
```

Resolve configuration errors and review policy violations before establishing a
baseline.

## 3. Create A Candidate Baseline

```bash
security-headers-auditor \
  --policy audit-policy.json \
  --write-baseline assurance-baseline.json \
  --format json \
  --output reports/assurance-initial.json
```

The tool never labels the baseline approved. Approval is an operator and change-
management decision. Review the target list, selected profiles, scores, findings,
methodology version, mapping version, and repository diff before commit.

## 4. Enforce Regressions

```bash
security-headers-auditor \
  --policy audit-policy.json \
  --baseline assurance-baseline.json \
  --format sarif \
  --output reports/assurance.sarif
```

For a test dashboard:

```bash
security-headers-auditor \
  --policy audit-policy.json \
  --baseline assurance-baseline.json \
  --format junit \
  --output reports/assurance.junit.xml
```

CI must use the process exit code as the gate. Merely uploading an artifact does
not enforce the result.

## 5. Review A Legitimate Change

When a regression is intentional:

1. verify system ownership and authorization;
2. confirm that the correct target and profile were used;
3. assess the security and compatibility impact;
4. update the policy when the requirement changed;
5. create a candidate baseline;
6. review the diff;
7. approve the new baseline through normal change control.

Never overwrite the baseline automatically after a failed run.

## Controlled Route Assurance

Use route assurance when one authorized origin has a small, known set of
security-relevant routes and reviewers need to identify drift between releases.
It is deliberately not an extension of the target-policy JSON: a route manifest
is a bounded comparison scope, while a policy expresses target-specific
requirements.

Create a candidate only after a complete comparison run, review the candidate
and manifest diff, then use the approved artifact on later runs:

```bash
security-headers-auditor \
  --route-comparison routes.json \
  --write-route-baseline candidates/routes.json \
  --format json \
  --output reports/routes-candidate.json

security-headers-auditor \
  --route-comparison routes.json \
  --route-baseline approved/routes.json \
  --format json \
  --output reports/routes-assurance.json
```

The candidate writer refuses an existing path, and the CLI rejects using a
baseline and writing a replacement in the same invocation. A mismatch in
manifest scope, methodology, or mapping set is an operational configuration
error; score and scored-control regression is an assurance failure. Route
artifacts include no raw response-header values. They remain security evidence
and should receive the same access control and retention review as other CI
artifacts.

## Methodology Migrations

Methodology versions are deliberate compatibility boundaries. Version `0.5.0`
adds controlled CSP parser semantics that can change a CSP score, so a v0.4
policy or baseline is rejected rather than silently reinterpreted. Copy the
current schema-compatible policy, review the response evidence and score
change, create a candidate baseline, then approve it through normal change
control. Do not edit an approved baseline's version field to bypass review.

## Reporting Readiness

Use `required` only when an owned reporting collector and operational workflow
exist. A valid endpoint without retention, access control, triage, and incident
response is configuration without assurance.

Reporting bodies may contain URLs, user-agent data, document addresses, and
violation samples. Collector privacy, minimization, sanitization, and retention
must be designed separately.

## Cross-Origin Isolation

Use `required` only when the application needs cross-origin isolation and the
complete resource graph has been tested. COOP/COEP changes can disrupt:

- federated sign-in;
- payment popups;
- opener relationships;
- embedded documents;
- third-party scripts, media, and fonts.

The header audit records response-level readiness. Browser QA must verify runtime
state and application compatibility.

## CI Artifact Handling

JSON, SARIF, JUnit, Markdown, and HTML outputs may expose:

- target hosts and paths;
- observed security posture;
- reporting endpoints;
- server and framework disclosure headers;
- policy decisions and exceptions.

Treat artifacts as security evidence. Apply access control, retention limits, and
redaction before external sharing.
