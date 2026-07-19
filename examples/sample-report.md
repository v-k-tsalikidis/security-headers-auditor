# Security Headers Audit Report

Methodology version: `0.3.0`

This deterministic excerpt uses the local brochure fixture. It demonstrates the
report structure without querying a remote website.

## Executive Summary

| Target | Profile | Confidence | Score | Summary | High | Medium | Low |
| --- | --- | --- | ---: | --- | ---: | ---: | ---: |
| `https://brochure.example.test/` | Public Brochure Site | medium | 82/100 | Moderate | 1 | 0 | 0 |

## https://brochure.example.test/

- Final URL: `https://www.example.test/`
- HTTP status: `200`
- Profile: `Public Brochure Site` (`brochure`)
- Detection confidence: `medium`
- Score: `82/100`
- Summary: `Moderate`

### Profile Decision

- HTML response without enough authenticated-application signals.
- Use `--profile app` when the endpoint belongs to an authenticated workflow.

### Profile-Scored Findings

| Header | Applicability | Status | Severity | Points | Evidence |
| --- | --- | --- | --- | ---: | --- |
| `Strict-Transport-Security` | required | pass | info | 30/30 | `max-age=31536000; includeSubDomains` |
| `Content-Security-Policy` | required | warning | high | 12/30 | `script-src` includes `'unsafe-inline'` without a nonce or hash |
| `X-Content-Type-Options` | required | pass | info | 15/15 | `nosniff` |
| `X-Frame-Options` | recommended | pass | info | 10/10 | `SAMEORIGIN` |
| `Referrer-Policy` | required | pass | info | 10/10 | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | recommended | pass | info | 5/5 | selected features disabled |

Contextual and information-disclosure observations are rendered separately. The
complete generated report also includes recommendations, scoring rationale,
version-pinned mappings, research links, authorization boundaries, and data-handling
guidance.

Use this tool only on systems you own, administer, or are authorized to assess.
A score expresses profile alignment, not proof of security or compliance.
