# Citation Manifest

Access review date: `2026-07-19`.

The manifest distinguishes normative specifications, official security guidance,
peer-reviewed research, and implementation references. Links in generated reports
are evidence trails. They do not transfer a source's authority to the project's
scoring model.

## Standards And Specifications

| Key | Source | Use |
| --- | --- | --- |
| `rfc-6797` | [RFC 6797: HTTP Strict Transport Security](https://www.rfc-editor.org/rfc/rfc6797) | HSTS syntax and behavior. |
| `w3c-csp3` | [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/) | CSP directives and processing model. |
| `w3c-referrer` | [Referrer Policy](https://www.w3.org/TR/referrer-policy/) | Referrer policy semantics. |
| `w3c-permissions` | [Permissions Policy](https://www.w3.org/TR/permissions-policy-1/) | Browser feature policy model. |
| `w3c-reporting` | [Reporting API](https://www.w3.org/TR/reporting-1/) | Modern Reporting-Endpoints syntax, trustworthiness, and delivery model. |
| `w3c-reporting-legacy` | [Reporting API Working Draft, September 2018](https://www.w3.org/TR/2018/WD-reporting-1-20180925/) | Historical Report-To compatibility interpretation. |
| `whatwg-fetch` | [Fetch Standard](https://fetch.spec.whatwg.org/) | CORP and related fetch behavior. |
| `whatwg-html` | [HTML Standard: Cross-origin opener policies](https://html.spec.whatwg.org/multipage/browsers.html#cross-origin-opener-policies) | COOP behavior. |
| `w3c-post-spectre` | [Post-Spectre Web Development](https://www.w3.org/TR/post-spectre-webdev/) | Cross-origin isolation architecture. |

## Security Standards And Official Guidance

| Key | Source | Use |
| --- | --- | --- |
| `asvs-5` | [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/raw/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv) | Version-pinned browser header requirements 3.4.1-3.4.8 and 3.5.8. |
| `owasp-secure-headers` | [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/) | Header coverage and deployment guidance. |
| `owasp-rest` | [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) | API-specific applicability and response guidance. |
| `owasp-csp-testing` | [OWASP WSTG: Testing for Content Security Policy](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/12-Test_for_Content_Security_Policy) | CSP review methodology. |
| `owasp-wstg-headers` | [OWASP WSTG-CONF-14: Testing Other HTTP Security Header Misconfigurations](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/14-Test_Other_HTTP_Security_Header_Misconfigurations) | Bounded HTTP security-header test-procedure alignment. |
| `nist-800-53r5` | [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) | Control-informed relationships only; not compliance testing. |
| `mitre-attack-m1021` | [MITRE ATT&CK M1021: Restrict Web-Based Content](https://attack.mitre.org/mitigations/M1021/) | Non-scoring CSP threat-mitigation context. |
| `mitre-attack-t1027-006` | [MITRE ATT&CK T1027.006: HTML Smuggling](https://attack.mitre.org/techniques/T1027/006/) | Related, non-scoring CSP mitigation context. |
| `mitre-d3fend-ach` | [MITRE D3FEND D3-ACH: Application Configuration Hardening](https://next.d3fend.mitre.org/technique/d3f%3AApplicationConfigurationHardening/) | Inferred, non-scoring defensive-technique context. |
| `oasis-sarif-2.1.0` | [OASIS SARIF 2.1.0 JSON Schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json) | Normative schema used to validate passing and regression CI artifacts. |

## Peer-Reviewed Research

| Key | Source | Use |
| --- | --- | --- |
| `csp-is-dead` | [CSP Is Dead, Long Live CSP!](https://dl.acm.org/doi/10.1145/2976749.2978363), ACM CCS 2016 | Evidence that allowlist-oriented CSP presence alone does not prove an effective policy. |

## Platform References

| Key | Source | Use |
| --- | --- | --- |
| `mdn-x-content-type` | [MDN: X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options) | `nosniff` implementation reference. |
| `mdn-x-frame-options` | [MDN: X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options) | Legacy framing value reference. |
| `mdn-clear-site-data` | [MDN: Clear-Site-Data](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Clear-Site-Data) | Contextual logout/reset guidance. |
| `mdn-cache-control` | [MDN: Cache-Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control) | Cache directive reference. |

## Versioned Evidence Mappings

Mapping set `2026.07.2` is stored in
`src/security_headers_auditor/data/compliance_evidence_v1.json`. Every mapping
contains a framework version, requirement identifier, relationship, rationale,
limitation, and citation source.

The fixed claims policy is `supporting-evidence-only`. Relationships such as
`supports`, `related`, and `legacy-support` do not mean `satisfies`, `certifies`,
or `complies with`.

The `2026.07.2` review replaces a stale WSTG-CONF-14 path and moves the
D3-ACH source to MITRE's current D3FEND endpoint. It reconfirms the exact
scope boundaries recorded in the framework-alignment policy; it does not
change scores or turn any mapping into a compliance decision.

The current set includes:

- HSTS: OWASP ASVS 5.0.0 V3.4.1 and NIST SP 800-53 Rev. 5 SC-8.
- CSP: OWASP ASVS 5.0.0 V3.4.3 and V3.4.6; NIST SC-18.
- CSP reporting readiness: OWASP ASVS 5.0.0 V3.4.7.
- `X-Content-Type-Options`: OWASP ASVS 5.0.0 V3.4.4.
- `Referrer-Policy`: OWASP ASVS 5.0.0 V3.4.5.
- legacy `X-Frame-Options`: supporting context for OWASP ASVS V3.4.6, which
  requires CSP `frame-ancestors` as the modern control.
- COOP and the cross-origin isolation bundle: OWASP ASVS 5.0.0 V3.4.8.
- CORP and resource isolation context: OWASP ASVS 5.0.0 V3.5.8.
