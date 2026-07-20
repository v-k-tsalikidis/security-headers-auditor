# Differentiation Brief

## Real-World Problem

Simple header checkers often apply a universal present/missing checklist. That can
penalize JSON APIs for absent browser document controls, reward weak values merely
because a header exists, and obscure the difference between a scored gap and a
contextual engineering decision.

## Product Position

Security Headers Auditor is a small, inspectable engineering tool for:

- security-conscious web owners and administrators;
- developers maintaining public sites, authenticated applications, or APIs;
- analysts who need evidence and reasoning, not only a grade;
- technical reviewers evaluating practical security judgment.

For the concise public narrative, practical comparison boundary, and visual
identity, see [Product Positioning](PRODUCT_POSITIONING.md). This brief remains
the detailed engineering rationale behind that narrative.

## Distinctive Decisions

- Three explicit response profiles: `app`, `api`, and `brochure`.
- Conservative, evidence-recording auto-detection with manual override.
- Profile-specific weights and applicability instead of a universal checklist.
- Partial credit for weak or incomplete values.
- Modern CSP `frame-ancestors` recognition rather than forcing legacy
  `X-Frame-Options`.
- Contextual and information-disclosure findings separated from the score.
- Coherent reporting-readiness and cross-origin-isolation capability analysis.
- Versioned evidence-only mappings with rationale and explicit limitations.
- Policy-as-code, approved baselines, and regression detection for continuous assurance.
- SARIF and JUnit outputs alongside Markdown, JSON, and self-contained HTML.
- URL data minimization and escaped untrusted evidence by default.
- Deterministic local fixtures with no remote dependency in regression tests.

## What It Does Not Claim

The project is not a vulnerability scanner, compliance engine, CSP validator,
monitoring service, browser runtime validator, replacement for Mozilla HTTP
Observatory, or substitute for application testing. Its score expresses profile
alignment only. Assurance outcomes express policy and drift state, not certification.

## Recruiter Signal

The repository demonstrates:

- risk-based security modelling and explicit non-goals;
- Python CLI and data-model design;
- policy-as-code and deterministic regression engineering;
- CI interoperability through SARIF and JUnit;
- standards and research traceability;
- secure report rendering;
- accessibility and privacy-aware product judgment;
- deterministic testing and release discipline;
- clear communication for technical and non-technical readers.
