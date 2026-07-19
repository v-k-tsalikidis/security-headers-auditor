---
name: security-headers-auditor
description: Continue and evolve the Security Headers Auditor as a premium, defensive, evidence-led HTTP response assurance product. Use for any implementation, review, testing, release, framework mapping, CLI, workspace, report, documentation, or frontend work in this repository.
---

# Security Headers Auditor

Build a trusted, read-only assurance tool for systems the operator owns, administers, or is explicitly authorized to assess. Prefer differentiated operational value over a generic header checklist.

## Product Bar

- Solve concrete engineering and assurance problems: profile-aware evaluation, weak-value analysis, evidence quality, actionable remediation, regression detection, and CI-grade outputs.
- Preserve the separation between observed evidence, engineering assessment, and compliance or certification claims. Never claim certification, legal compliance, exploitability, or security assurance that the tool cannot prove.
- Map controls to authoritative, version-pinned security frameworks only with explicit scope, rationale, limitations, and source provenance. Treat mappings as supporting evidence.
- Favor fast, deterministic, offline-testable behavior and reports that expose the reasoning behind every score and conclusion.

## Safety and Privacy

- Keep all network behavior read-only, bounded, authorized, and explicit. Do not crawl, authenticate, fuzz, exploit, brute-force, bypass controls, or follow out-of-scope redirects.
- Preserve URL redaction and default-deny scope controls. Reject unsafe schemes, embedded credentials, private or loopback targets when the workspace policy requires public scope, and untrusted redirects.
- Treat response headers, URLs, report data, imports, and frontend input as untrusted. Escape rendered output, validate schemas at boundaries, cap resource use, and never persist raw sensitive data unless an explicit, documented policy allows it.
- Make local workspace functionality loopback-only, origin-checked, token-protected, revision-safe, and least-privilege on disk.

## Quality Gate

1. Read the current release gate, methodology specification, threat model, roadmap, ADRs, framework-alignment policy, tests, and existing implementation before proposing a new capability.
2. Define the real user problem, intended authorized use, non-goals, threat impact, framework-evidence impact, and measurable acceptance criteria.
3. Add or update deterministic tests before treating a behavior as complete. Cover invalid, malicious, boundary, privacy, and regression cases as well as expected success paths.
4. Validate the Python suite, frontend tests, type check, production build, and rendered browser behavior when a UI changes. Run integration tests with permitted loopback networking.
5. Do not publish, announce, tag, or call a release complete until the relevant release gate, security review, documentation, tests, CI, browser QA, and accessibility evidence are complete.

## Delivery

Preserve existing user changes and never reset, delete, or overwrite work to simplify a change. Keep commits focused and inspect staged diffs for secrets, generated output, dependencies, and unrelated files. Update this skill when the product constraints, architecture, validation commands, or release rules materially change.
