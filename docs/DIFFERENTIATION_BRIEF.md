# Differentiation Brief

## Problem

Many small teams, portfolio owners, WordPress administrators, and non-specialist site owners need a quick way to understand whether their websites expose basic browser-side hardening gaps. Existing tools are useful, but they often return a grade without making the reasoning easy to reuse in a small operational note, website maintenance report, or recruiter-readable portfolio artifact.

## Target User

- Security-conscious website owner or administrator.
- Freelance web designer/developer who wants lightweight security hygiene checks.
- Junior analyst or SOC/GRC learner who needs transparent assessment output.
- Recruiter or technical reviewer evaluating practical cybersecurity judgment.

## Existing Solution Landscape

- Mozilla HTTP Observatory provides mature scoring and grading for public websites.
- OWASP Secure Headers Project maintains extensive guidance and validation material.
- Browser and web-platform documentation from MDN and web.dev explains the purpose and limitations of individual headers.
- Many small scripts only check whether a header exists.

## Gaps To Avoid

- Treating every header as equally important.
- Treating all present headers as strong.
- Penalizing context-dependent headers without explanation.
- Producing noisy output that is difficult to turn into a maintenance note.
- Implying that security headers prove that a site is secure.

## Design Direction

This project stays deliberately small, but it should show mature judgment:

- baseline controls are weighted;
- weak values receive partial credit and review notes;
- contextual headers are separated from the score;
- information-disclosure headers are visible without overstating risk;
- output is readable as a short assessment note.

## Public-Safe Scope

The tool performs read-only HTTP `HEAD` requests with `GET` fallback. It does not crawl, exploit, brute-force, fuzz, authenticate, bypass controls, or inspect private content. Users must provide the targets and must have authorization to assess them.

## Recruiter Signal

This repository is intended to demonstrate:

- practical web security hygiene;
- Python CLI design;
- structured findings and reporting;
- risk-aware scoring rather than checklist-only thinking;
- ability to connect official guidance with lightweight implementation.

## Deliberate Exclusions

- No vulnerability scanning.
- No exploit checks.
- No browser automation in the MVP.
- No claim of equivalence with Mozilla HTTP Observatory or OWASP tools.
- No default use of third-party scanning APIs.

## Evidence Of Quality

- Unit tests for normalization, scoring, weak values, and disclosure observations.
- Clear methodology document.
- Deterministic sample report.
- Public-safety disclaimer.
- Roadmap that expands carefully without turning the tool into a noisy scanner.
