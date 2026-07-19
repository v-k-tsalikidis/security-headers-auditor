# Security Headers Audit Report

Methodology version: `0.4.0`

Evidence mapping set: `2026.07.2`

This deterministic excerpt uses the local authenticated-application fixture. It
demonstrates the profile score, assurance controls, and approved-baseline outcome
without querying a remote website.

## Executive Summary

| Target | Profile | Confidence | Score | Summary |
| --- | --- | --- | ---: | --- |
| `https://secure.example.test/dashboard` | Authenticated Web Application | explicit | 100/100 | Strong |

## Continuous Assurance

- Policy: `fixture-assurance`
- Outcome: `passed`
- Exit code: `0`
- Policy violations: `0`
- Regressions: `0`
- Operational errors: `0`

## https://secure.example.test/dashboard

- Final URL: `https://secure.example.test/dashboard`
- HTTP status: `200`
- Profile: `Authenticated Web Application` (`app`)
- Detection confidence: `explicit`
- Score: `100/100`
- Summary: `Strong`

### Profile Decision

- Profile selected explicitly by the approved policy.

### Profile-Scored Findings

| Header | Applicability | Status | Severity | Points | Evidence |
| --- | --- | --- | --- | ---: | --- |
| `Strict-Transport-Security` | required | pass | info | 20/20 | `max-age=31536000; includeSubDomains` |
| `Content-Security-Policy` | required | pass | info | 25/25 | application-specific policy with `report-to csp` |
| `X-Content-Type-Options` | required | pass | info | 10/10 | `nosniff` |
| `X-Frame-Options` | recommended | pass | info | 5/5 | `SAMEORIGIN` |
| `Referrer-Policy` | required | pass | info | 10/10 | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | recommended | pass | info | 10/10 | selected features disabled |
| `Cross-Origin-Opener-Policy` | recommended | pass | info | 10/10 | `same-origin` |
| `Cross-Origin-Resource-Policy` | recommended | pass | info | 10/10 | `same-origin` |

### Assurance Controls

| Control | Expectation | Status | Interpretation |
| --- | --- | --- | --- |
| Reporting Endpoints | required | pass | CSP reporting group resolves to a trustworthy endpoint |
| CSP Reporting Readiness | required | pass | `report-to` is linked to the configured group |
| Cross-Origin Isolation Bundle | required | pass | response-level COOP/COEP prerequisites are present |

Contextual and information-disclosure observations are rendered separately. The
complete generated report also includes recommendations, scoring rationale,
version-pinned mappings with limitations, research links, regression diagnostics,
authorization boundaries, and data-handling guidance.

Use this tool only on systems you own, administer, or are authorized to assess.
A score expresses profile alignment, not proof of security or compliance.
