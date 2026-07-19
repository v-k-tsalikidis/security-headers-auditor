# v0.4.0 Release Gate

## Release Classification

Current classification: **complete**.

Version 0.4.0 must not be labelled complete until every applicable item below is
recorded as passed.

## Functional Gates

- [x] Existing profile scores remain stable for deterministic v0.3 fixtures.
- [x] Reporting-Endpoints syntax and trustworthiness checks pass.
- [x] CSP report-to linkage and legacy report-uri behavior pass.
- [x] Cross-origin isolation bundle states pass for complete, partial, absent, and invalid fixtures.
- [x] Policy parser rejects unknown fields, invalid controls, incompatible versions, and implicit auto profiles.
- [x] Approved-baseline comparison detects profile, score, status, and new-finding regressions.
- [x] Equivalent runs produce byte-stable baseline JSON.
- [x] Exit codes `0`, `1`, and `2` are exercised.

## CI Output Gates

- [x] Assurance JSON parses and records versions, outcome, and exit code.
- [x] SARIF validates as version 2.1.0 and contains stable rule identifiers.
- [x] JUnit XML parses and distinguishes failures from operational errors.
- [x] GitHub Actions Python 3.10, 3.11, and 3.12 matrix is green.
- [x] Workflow artifacts contain JSON, SARIF, JUnit, and baseline outputs.

## Security And Privacy Gates

- [x] Query and fragment redaction remains effective.
- [x] Baselines exclude raw header values and runtime timestamps.
- [x] HTML and Markdown escape hostile evidence.
- [x] HTML remains script-free and free of remote runtime dependencies.
- [x] Policy, baseline, reporting, and CI artifact privacy boundaries are documented.
- [x] Redirect authorization behavior remains unchanged.

## Accessibility And Browser Gates

- [x] Desktop Chromium report review passes.
- [x] Mobile Chromium report review passes.
- [x] Assurance tables remain keyboard-scrollable.
- [x] Disclosure controls, skip link, focus indicators, labels, and reduced-motion behavior remain present.
- [x] Text and status colors retain documented contrast.
- [x] No overlap, clipping, or horizontal page overflow is observed.

## Packaging And Documentation Gates

- [x] Compliance evidence JSON is included in wheel and editable installs.
- [x] Offline wheel install and CLI execution pass.
- [x] Policy and baseline JSON Schemas parse.
- [x] README, methodology, continuous assurance guide, citation manifest, privacy boundaries, and release notes align with implementation.
- [x] Repository diff contains no generated reports, secrets, caches, or unrelated changes.

## Evidence

- Unit tests: `69` deterministic tests passed on local Python `3.12`.
- Compile check: `python3 -m compileall -q src tests` passed.
- Local deterministic CLI: pass=`0`, regression=`1`, incompatible policy=`2`;
  committed baseline regeneration is byte-identical.
- SARIF/JUnit parse: passing and regression SARIF validated against the
  [official OASIS 2.1.0 schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json);
  passing JUnit `1/0/0`; failing JUnit records target, control, previous,
  and current state.
- Browser QA: Chromium desktop plus `390x844` and `320x700` mobile
  viewports; no console errors or external runtime assets.
- Contrast: minimum measured text/status pair `5.19:1`; focus indicator
  `7.28:1`.
- Wheel build/install: `security_headers_auditor-0.4.0-py3-none-any.whl`;
  offline install and installed CLI assurance run passed.
- GitHub Actions: [run 29682900732](https://github.com/v-k-tsalikidis/security-headers-auditor/actions/runs/29682900732)
  completed successfully for Python `3.10`, `3.11`, and `3.12`.
- Hosted artifacts: all three matrix archives contain exactly
  `assurance.json`, `assurance.sarif`, `assurance.junit.xml`, and
  `assurance-candidate-baseline.json`; every candidate baseline is
  byte-identical with the committed fixture baseline.
- Final diff: `git diff --check` passed; ignored build/cache output is not
  part of the repository diff.
