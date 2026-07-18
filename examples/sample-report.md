# Security Headers Audit Report

This report is informational and based on read-only HTTP response header checks.

Scoring focuses on baseline browser security signals. Contextual headers and information-disclosure observations are reported separately because their value depends on application type, endpoint sensitivity, and compatibility constraints.

## Executive Summary

| Target | Score | Summary | High | Medium | Low |
| --- | ---: | --- | ---: | ---: | ---: |
| `https://example.test` | 58/100 | Needs Review | 2 | 3 | 0 |

## https://example.test

- Final URL: `https://example.test`
- HTTP status: `200`
- Score: `58/100`
- Summary: `Needs Review`

### Baseline Findings

| Header | Status | Severity | Points | Evidence | Recommendation |
| --- | --- | --- | ---: | --- | --- |
| `Strict-Transport-Security` | warning | medium | 10/20 | max-age=300 | Serve over HTTPS and use max-age of at least 31536000 seconds; consider 63072000 and includeSubDomains after domain readiness review. |
| `Content-Security-Policy` | warning | high | 10/20 | default-src *; script-src 'unsafe-inline' | Define a site-specific CSP. Prefer default-src/script-src controls, object-src 'none', base-uri 'self' or 'none', and frame-ancestors where possible. |
| `X-Content-Type-Options` | pass | info | 10/10 | nosniff | Use X-Content-Type-Options: nosniff. |
| `X-Frame-Options` | warning | medium | 5/10 | ALLOW-FROM https://legacy.example | Use DENY or SAMEORIGIN, or use CSP frame-ancestors with awareness that older clients may still rely on X-Frame-Options. |
| `Referrer-Policy` | warning | high | 2.5/10 | unsafe-url | Prefer no-referrer, same-origin, strict-origin, or strict-origin-when-cross-origin depending on application needs. |
| `Permissions-Policy` | warning | medium | 5/10 | geolocation=* | Disable unused powerful browser features explicitly. |
| `Cross-Origin-Opener-Policy` | warning | medium | 5/10 | unsafe-none | Use same-origin unless the application requires a looser opener policy. |
| `Cross-Origin-Resource-Policy` | pass | info | 10/10 | same-origin | Use same-origin or same-site for sensitive resources where compatible. |

### Contextual Checks

| Header | Status | Evidence / Note | Recommendation |
| --- | --- | --- | --- |
| `Cross-Origin-Embedder-Policy` | info | Supports cross-origin isolation for applications that need advanced browser capabilities. This is context-dependent and is not included in the score. | Evaluate require-corp only when the application is ready for cross-origin isolation. |
| `Clear-Site-Data` | info | Can clear browser-side state on sensitive flows such as logout. This is context-dependent and is not included in the score. | Consider on logout or account-reset endpoints, not necessarily every response. |
| `Cache-Control` | info | Can prevent sensitive content from remaining in local browser caches. This is context-dependent and is not included in the score. | Use no-store for authenticated or sensitive responses. |
| `X-Permitted-Cross-Domain-Policies` | info | Restricts legacy cross-domain policy files. This is context-dependent and is not included in the score. | Use none unless legacy client requirements justify otherwise. |
| `X-DNS-Prefetch-Control` | info | Controls DNS prefetching for privacy-sensitive pages. This is context-dependent and is not included in the score. | Consider off on pages with sensitive or private content. |

### Information-Disclosure Observations

| Header | Value | Note |
| --- | --- | --- |
| `Server` | Apache/2.4.6 | May disclose web server or platform details. |
| `X-Powered-By` | PHP/7.4 | May disclose framework, language, or hosting details. |

## Disclaimer

This tool is an independent educational project. Use it only on systems you own, administer, or are authorized to assess.

A strong score does not prove that an application is secure. A weak score means that baseline browser-side hardening should be reviewed.
